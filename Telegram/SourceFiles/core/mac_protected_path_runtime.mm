/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/mac_protected_path_runtime.h"

#include "settings.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QMutexLocker>

#include <Cocoa/Cocoa.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <pwd.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace Core::MacProtectedPath {
namespace {

struct RuntimeState final {
	QMutex mutex;
	bool initialized = false;
	bool ready = false;
	QString initialWorkingDirectory;
	QString ipcDirectory;
	QString profile;
	std::shared_ptr<const MacProtectedPathPolicy> policy;
	RefusalLog refusals;
};

[[nodiscard]] RuntimeState &State() {
	static auto result = RuntimeState();
	return result;
}

[[nodiscard]] QByteArray AccountDatabaseHome() {
	const auto suggested = sysconf(_SC_GETPW_R_SIZE_MAX);
	const auto size = size_t(
		(suggested > 0 && suggested <= 1024 * 1024) ? suggested : 16384);
	auto buffer = std::vector<char>(size);
	struct passwd entry = {};
	auto result = static_cast<passwd *>(nullptr);
	if (getpwuid_r(getuid(), &entry, buffer.data(), buffer.size(), &result)
		|| !result || !result->pw_dir) {
		return {};
	}
	return QByteArray(result->pw_dir);
}

[[nodiscard]] QByteArray FoundationHome() {
	@autoreleasepool {
		const auto home = NSHomeDirectory();
		const auto path = [home fileSystemRepresentation];
		return path ? QByteArray(path) : QByteArray();
	}
}

[[nodiscard]] HomeRoots NativeHomeRoots() {
	auto result = HomeRoots{.accountDatabase = AccountDatabaseHome(),
							.environment = qgetenv("HOME"),
							.foundation = FoundationHome()};
#if defined(TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST)
	const auto testHome = qgetenv("TDESKTOP_MAC_PROFILE_TEST_HOME");
	if (!testHome.isEmpty()) {
		result.accountDatabase = testHome;
		result.foundation = testHome;
	}
#endif
	return result;
}

[[nodiscard]] FileError FileErrorFromErrno(int value) {
	switch (value) {
	case ENOENT:
		return FileError::Missing;
	case ENOTDIR:
		return FileError::NotDirectory;
	case ELOOP:
		return FileError::Loop;
	default:
		return FileError::Unexpected;
	}
}

[[nodiscard]] LstatResult NativeLstat(const QByteArray &path) {
	struct stat info = {};
	if (::lstat(path.constData(), &info)) {
		return {.error = FileErrorFromErrno(errno)};
	}
	const auto type = S_ISDIR(info.st_mode)	  ? FileType::Directory
					  : S_ISREG(info.st_mode) ? FileType::Regular
					  : S_ISLNK(info.st_mode) ? FileType::Symlink
											  : FileType::Other;
	return {.type = type, .error = FileError::None};
}

[[nodiscard]] ReadlinkResult NativeReadlink(const QByteArray &path) {
	auto size = size_t(1024);
	while (size <= 65536) {
		auto target = QByteArray(int(size), Qt::Uninitialized);
		const auto count = ::readlink(path.constData(), target.data(),
									  size_t(target.size()));
		if (count < 0) {
			return {.error = FileErrorFromErrno(errno)};
		}
		if (size_t(count) < size) {
			target.resize(int(count));
			return {.target = std::move(target), .error = FileError::None};
		}
		size *= 2;
	}
	return {.error = FileError::Unexpected};
}

[[nodiscard]] FileSystem NativeFileSystem() {
	return {.lstat = NativeLstat, .readlink = NativeReadlink};
}

[[nodiscard]] QString OperationName(Operation operation) {
	switch (operation) {
	case Operation::Open:
		return u"open"_q;
	case Operation::Read:
		return u"read"_q;
	case Operation::Write:
		return u"write"_q;
	case Operation::Stat:
		return u"stat"_q;
	case Operation::Lstat:
		return u"lstat"_q;
	case Operation::OpenDir:
		return u"opendir"_q;
	case Operation::GetAttrList:
		return u"getattrlist"_q;
	case Operation::Mkdir:
		return u"mkdir"_q;
	case Operation::Lock:
		return u"lock"_q;
	case Operation::Rename:
		return u"rename"_q;
	case Operation::Copy:
		return u"copy"_q;
	case Operation::Link:
		return u"link"_q;
	case Operation::Unlink:
		return u"unlink"_q;
	case Operation::Rmdir:
		return u"rmdir"_q;
	case Operation::RecursiveDelete:
		return u"recursive-delete"_q;
	}
	return u"unknown"_q;
}

[[nodiscard]] QString ProtectedClassName(ProtectedClass protectedClass) {
	switch (protectedClass) {
	case ProtectedClass::None:
		return u"none"_q;
	case ProtectedClass::ApplicationSupport:
		return u"application-support"_q;
	case ProtectedClass::Container:
		return u"container"_q;
	case ProtectedClass::GroupContainer:
		return u"group-container"_q;
	case ProtectedClass::BundleKeyed:
		return u"bundle-keyed"_q;
	case ProtectedClass::Invalid:
		return u"invalid"_q;
	}
	return u"unknown"_q;
}

void ReportRefusal(const RefusalRecord &refusal) {
	if (!State().refusals.record(refusal)) {
		return;
	}
	const auto message
		= u"Mac protected path refusal: operation=%1 class=%2 callsite=%3"_q
			  .arg(OperationName(refusal.operation),
				   ProtectedClassName(refusal.protectedClass),
				   refusal.callsite);
	fprintf(stderr, "%s\n", message.toUtf8().constData());
}

void ReportInvalidInitialization(const QString &callsite) {
	ReportRefusal({.operation = Operation::Open,
				   .protectedClass = ProtectedClass::Invalid,
				   .callsite = callsite});
}

[[nodiscard]] bool AppSandboxed() {
#ifdef OS_MAC_STORE
	return true;
#else  // OS_MAC_STORE
	return false;
#endif // !OS_MAC_STORE
}

} // namespace

bool IntegrationTestActive() {
#if defined(TDESKTOP_TEAGRAM)                                                  \
	&& defined(TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST)
	return qEnvironmentVariable("TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST")
		   == "1";
#else
	return false;
#endif
}

bool InitializeProfile() {
	if (!IntegrationTestActive()) {
		if (qEnvironmentVariable("TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST")
			== "1") {
			ReportInvalidInitialization(u"profile.integration-test-build"_q);
			return false;
		}
		return true;
	}
	const auto initialWorkingDirectory = QDir::currentPath() + '/';
	auto &state = State();
	{
		QMutexLocker lock(&state.mutex);
		if (state.initialized) {
			return state.ready;
		}
		state.initialized = true;
		state.initialWorkingDirectory = initialWorkingDirectory;
	}

	const auto homes = NativeHomeRoots();
	const auto filesystem = NativeFileSystem();
	auto failure = RefusalRecord();
	const auto policy
		= MacProtectedPathPolicy::Build(homes, filesystem, &failure);
	if (!policy.valid()) {
		ReportRefusal(failure);
		return false;
	}
	const auto profileBytes = TeagramProfileRoot(homes, AppSandboxed());
	if (profileBytes.isEmpty()) {
		ReportInvalidInitialization(u"profile.home-source"_q);
		return false;
	}
	const auto profile
		= policy.Resolve(Operation::Open, profileBytes, homes.accountDatabase,
						 u"profile.root"_q);
	if (!profile.allowed()) {
		ReportRefusal(profile.refusal);
		return false;
	}
	const auto profilePath = QString::fromUtf8(profile.resolvedPath);
	const auto create
		= policy.Resolve(Operation::Mkdir, profile.resolvedPath,
						 homes.accountDatabase, u"profile.create"_q);
	if (!create.allowed()) {
		ReportRefusal(create.refusal);
		return false;
	}
	if (!QDir().mkpath(profilePath)) {
		ReportInvalidInitialization(u"profile.mkdir"_q);
		return false;
	}

	const auto appSandboxed = AppSandboxed();
	const auto ipcDirectory
		= appSandboxed ? QString::fromUtf8(homes.foundation) + u"/tmp"_q
					   : u"/tmp"_q;
	cForceWorkingDir(profilePath + '/');
	{
		QMutexLocker lock(&state.mutex);
		state.ipcDirectory = ipcDirectory;
		state.profile = cWorkingDir();
		state.policy = std::make_shared<MacProtectedPathPolicy>(policy);
		state.ready = true;
	}
	if (IntegrationTestActive()) {
		const auto path = ipcDirectory.toUtf8();
		fprintf(stderr, "Mac profile IPC selected: variant=%s directory=%s\n",
				appSandboxed ? "build_macstore" : "non-store",
				path.constData());
	}
	return true;
}

QString InitialWorkingDirectory() {
	if (!IntegrationTestActive()) {
		return {};
	}
	auto &state = State();
	QMutexLocker lock(&state.mutex);
	return state.initialWorkingDirectory;
}

QString ProfileRoot() {
	if (!IntegrationTestActive()) {
		return {};
	}
	auto &state = State();
	QMutexLocker lock(&state.mutex);
	return state.ready ? state.profile : QString();
}

QString NotificationSoundsDirectory() {
	const auto home = NativeHomeRoots().foundation;
	return home.isEmpty() ? QString()
						  : QString::fromUtf8(home) + u"/Library/Sounds"_q;
}

QString IpcDirectory() {
	if (IntegrationTestActive()) {
		auto &state = State();
		QMutexLocker lock(&state.mutex);
		return state.ready ? state.ipcDirectory : QString();
	}
	if (AppSandboxed()) {
		const auto home = FoundationHome();
		return home.isEmpty() ? QString() : QString::fromUtf8(home) + u"/tmp"_q;
	}
	return u"/tmp"_q;
}

bool CheckPathAt(Operation operation, const QString &path,
				 const QString &anchor, const char *callsite) {
	if (!IntegrationTestActive()) {
		return true;
	}
	auto policy = std::shared_ptr<const MacProtectedPathPolicy>();
	{
		auto &state = State();
		QMutexLocker lock(&state.mutex);
		if (!state.ready || !state.policy) {
			ReportInvalidInitialization(u"operation.before-profile"_q);
			return false;
		}
		policy = state.policy;
	}
	const auto result = policy->Resolve(operation, QFile::encodeName(path),
										QFile::encodeName(anchor),
										QString::fromUtf8(callsite));
	if (!result.allowed()) {
		ReportRefusal(result.refusal);
		return false;
	}
	return true;
}

bool CheckPath(Operation operation, const QString &path, const char *callsite) {
	if (!IntegrationTestActive()) {
		return true;
	}
	auto anchor = QString();
	{
		auto &state = State();
		QMutexLocker lock(&state.mutex);
		if (!state.ready || !state.policy) {
			ReportInvalidInitialization(u"operation.before-profile"_q);
			return false;
		}
		anchor = state.profile;
	}
	return CheckPathAt(operation, path, anchor, callsite);
}

bool CheckExternalPath(Operation operation, const QString &path,
					   const char *callsite) {
	return CheckPathAt(operation, path, QString(), callsite);
}

namespace {

bool CheckCachePathImpl(
	const QString &path, const char *callsite,
	const std::function<void(const QString &)> &beforeEntryStat) {
	if (!IntegrationTestActive()) {
		return true;
	}
	if (!CheckPath(Operation::OpenDir, path, callsite)) {
		return false;
	}
	auto allowed = true;
	auto directories = std::vector<QString>{path};
	auto visited = std::set<QString>();
	while (!directories.empty()) {
		const auto directory = std::move(directories.back());
		directories.pop_back();
		if (!CheckPath(Operation::OpenDir, directory, callsite)) {
			allowed = false;
			continue;
		}
		const auto canonical = QFileInfo(directory).canonicalFilePath();
		const auto identity
			= canonical.isEmpty() ? QDir::cleanPath(directory) : canonical;
		if (!visited.emplace(identity).second) {
			continue;
		}
		const auto native = QFile::encodeName(directory);
		const auto descriptor
			= ::open(native.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (descriptor < 0) {
			if (errno != ENOENT) {
				allowed = false;
			}
			continue;
		}
		const auto stream = fdopendir(descriptor);
		if (!stream) {
			::close(descriptor);
			allowed = false;
			continue;
		}
		const auto close = gsl::finally([=] { closedir(stream); });
		while (const auto entry = readdir(stream)) {
			const auto local = entry->d_name;
			if (!std::strcmp(local, ".") || !std::strcmp(local, "..")) {
				continue;
			}
			const auto name = QFile::decodeName(local);
			const auto child = QDir(directory).filePath(name);
			if (!CheckPath(Operation::Open, child, callsite)) {
				allowed = false;
				continue;
			}
			if (beforeEntryStat) {
				beforeEntryStat(child);
			}
			struct stat info = {};
			if (fstatat(dirfd(stream), local, &info, AT_SYMLINK_NOFOLLOW)
				!= 0) {
				if (errno != ENOENT) {
					allowed = false;
				}
				continue;
			}
			if (S_ISDIR(info.st_mode)) {
				if (!CheckPath(Operation::OpenDir, child, callsite)) {
					allowed = false;
					continue;
				}
				directories.push_back(child);
			} else if (S_ISLNK(info.st_mode)) {
				if (!CheckPath(Operation::OpenDir, child, callsite)) {
					allowed = false;
					continue;
				}
				if (fstatat(dirfd(stream), local, &info, 0) != 0) {
					if (errno != ENOENT) {
						allowed = false;
					}
				} else if (S_ISDIR(info.st_mode)) {
					directories.push_back(child);
				}
			}
		}
	}
	return allowed;
}

} // namespace

bool CheckCachePath(const QString &path, const char *callsite) {
	return CheckCachePathImpl(path, callsite, {});
}

#if defined(TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST)
bool CheckCachePathForTesting(
	const QString &path, const char *callsite,
	std::function<void(const QString &)> beforeEntryStat) {
	return CheckCachePathImpl(path, callsite, beforeEntryStat);
}
#endif

bool CheckPair(Operation operation, const QString &first, const QString &second,
			   const char *callsite) {
	if (!IntegrationTestActive()) {
		return true;
	}
	auto policy = std::shared_ptr<const MacProtectedPathPolicy>();
	auto anchor = QString();
	{
		auto &state = State();
		QMutexLocker lock(&state.mutex);
		if (!state.ready || !state.policy) {
			ReportInvalidInitialization(u"operation.before-profile"_q);
			return false;
		}
		policy = state.policy;
		anchor = state.profile;
	}
	const auto result = policy->ResolvePair(
		operation, QFile::encodeName(first), QFile::encodeName(second),
		QFile::encodeName(anchor), QString::fromUtf8(callsite));
	if (!result.first.allowed()) {
		ReportRefusal(result.first.refusal);
	}
	if (!result.second.allowed()) {
		ReportRefusal(result.second.refusal);
	}
	return result.allowed();
}

} // namespace Core::MacProtectedPath
