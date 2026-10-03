/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "core/core_settings_external_paths.h"
#include "core/file_location.h"
#include "core/mac_protected_path_access.h"
#include "core/mac_protected_path_policy.h"
#include "storage/details/storage_theme_path.h"

#include <QtCore/QDataStream>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QTemporaryDir>

#include <map>
#include <vector>

namespace {

using namespace Core::MacProtectedPath;

struct FakeFileSystem final {
	std::map<QByteArray, LstatResult> entries;
	std::map<QByteArray, ReadlinkResult> links;
	std::vector<QByteArray> lstatCalls;
	std::vector<QByteArray> readlinkCalls;
	std::vector<QByteArray> openCalls;

	[[nodiscard]] FileSystem operations() {
		return {
			.lstat = [this](const QByteArray &path) {
				lstatCalls.push_back(path);
				const auto i = entries.find(path);
				return (i == entries.end())
					? LstatResult{ .error = FileError::Missing }
					: i->second;
			},
			.readlink = [this](const QByteArray &path) {
				readlinkCalls.push_back(path);
				const auto i = links.find(path);
				return (i == links.end())
					? ReadlinkResult{ .error = FileError::Unexpected }
					: i->second;
			},
			.open = [this](const QByteArray &path) {
				openCalls.push_back(path);
			}
		};
	}
};

[[nodiscard]] MacProtectedPathPolicy TestPolicy(FakeFileSystem &fs) {
	fs.entries.emplace(
		"/Users",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Users/alice",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	return MacProtectedPathPolicy::Build(
		HomeRoots{
			.accountDatabase = "/Users/alice",
			.foundation = "/Users/alice" },
		fs.operations());
}

void ClearCalls(FakeFileSystem &fs) {
	fs.lstatCalls.clear();
	fs.readlinkCalls.clear();
	fs.openCalls.clear();
}

void AddDirectoryHierarchy(FakeFileSystem &fs, const QByteArray &path) {
	auto current = QByteArray();
	for (const auto &part : path.split('/')) {
		if (part.isEmpty()) {
			continue;
		}
		current.append('/');
		current.append(part);
		fs.entries.emplace(current, LstatResult{.type = FileType::Directory,
												.error = FileError::None});
	}
}

TEST_CASE(TeagramProfileRootUsesTrustedHomeSource) {
	const auto homes = HomeRoots{
		.accountDatabase = "/Users/alice",
		.environment = "/Users/alice/Library/Group "
					   "Containers/6N38VWS5BX.ru.keepcoder.Telegram",
		.foundation
		= "/Users/alice/Library/Containers/io.teagram.desktop/Data"};
	CHECK_EQ(TeagramProfileRoot(homes, false),
			 QByteArray("/Users/alice/Library/Application Support/Teagram"));
	CHECK_EQ(
		TeagramProfileRoot(homes, true),
		QByteArray("/Users/alice/Library/Containers/io.teagram.desktop/Data/"
				   "Library/Application Support/Teagram"));
}

void CheckRefusedWithoutProtectedProbe(
		const MacProtectedPathPolicy &policy,
		FakeFileSystem &fs,
		const QByteArray &path,
		ProtectedClass protectedClass) {
	ClearCalls(fs);
	const auto result = policy.Resolve(
		Operation::Open,
		path,
		{},
		u"unit.probe"_q);
	CHECK(!result.allowed());
	CHECK(result.refusal.protectedClass == protectedClass);
	CHECK(result.resolvedPath.isEmpty());
	CHECK(fs.openCalls.empty());
	for (const auto &call : fs.lstatCalls) {
		CHECK(policy.Classify(call) == ProtectedClass::None);
	}
	for (const auto &call : fs.readlinkCalls) {
		CHECK(policy.Classify(call) == ProtectedClass::None);
	}
}

} // namespace

TEST_CASE(GroupContainerRefusesBeforeProtectedProbe) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	CHECK(policy.valid());

	const auto result = policy.Resolve(
		Operation::Open,
		"/Users/alice/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/tdata/x",
		{},
		u"unit.group-container"_q);
	CHECK(!result.allowed());
	CHECK(result.refusal.protectedClass == ProtectedClass::GroupContainer);
	CHECK(result.refusal.operation == Operation::Open);
	CHECK_EQ(result.refusal.callsite, u"unit.group-container"_q);
	CHECK(fs.openCalls.empty());
	CHECK(fs.readlinkCalls.empty());
	for (const auto &call : fs.lstatCalls) {
		CHECK(policy.Classify(call) != ProtectedClass::GroupContainer);
	}
}

TEST_CASE(AllProtectedRootsUseComponentMatching) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	const auto protectedPaths = std::vector<
		std::pair<QByteArray, ProtectedClass>>{
		{"/Users/alice/Library/Application Support/Telegram Desktop/tdata/x",
		 ProtectedClass::ApplicationSupport},
		{"/Users/alice/Library/Containers/org.telegram.desktop/Data/x",
		 ProtectedClass::Container},
		{"/Users/alice/Library/Containers/ru.keepcoder.Telegram/Data/x",
		 ProtectedClass::Container},
		{"/Users/alice/Library/Group "
		 "Containers/6N38VWS5BX.ru.keepcoder.Telegram/tdata/x",
		 ProtectedClass::GroupContainer},
		{"/Users/alice/Library/Preferences/com.tdesktop.Telegram.plist",
		 ProtectedClass::BundleKeyed},
		{"/Users/alice/Library/Caches/org.telegram.desktop/data",
		 ProtectedClass::BundleKeyed},
		{"/Users/alice/Library/HTTPStorages/ru.keepcoder.Telegram.shared/data",
		 ProtectedClass::BundleKeyed},
		{"/Users/alice/Library/WebKit/com.tdesktop.Telegram/WebsiteData",
		 ProtectedClass::BundleKeyed},
		{"/Users/alice/Library/Saved Application "
		 "State/org.telegram.desktop.savedState",
		 ProtectedClass::BundleKeyed},
	};
	for (const auto &[path, protectedClass] : protectedPaths) {
		CHECK(policy.Classify(path) == protectedClass);
		CheckRefusedWithoutProtectedProbe(policy, fs, path, protectedClass);
	}

	const auto allowedPaths = std::vector<QByteArray>{
		"/Users/alice/Library/Application Support/Teagram/tdata/x",
		"/Users/alice/Library/Application Support/Telegram Desktop.bak/tdata/x",
		"/Users/alice/Library/Containers/com.example.other/Data/x",
		"/Users/alice/Library/Group Containers/Signal/tdata/x",
		"/Users/alice/Library/Preferences/io.teagram.desktop.plist",
	};
	for (const auto &path : allowedPaths) {
		CHECK(policy.Classify(path) == ProtectedClass::None);
		ClearCalls(fs);
		const auto result = policy.Resolve(
			Operation::Open,
			path,
			{},
			u"unit.allowed"_q);
		CHECK(result.allowed());
	}
}

TEST_CASE(CaseNormalizationAndFirmlinkAliasesMatch) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);

	const auto mixedCase = QByteArray(
		"/uSeRs/ALICE/lIbRaRy/aPpLiCaTiOn sUpPoRt/telegram desktop/tdata");
	CHECK(policy.Classify(mixedCase) == ProtectedClass::ApplicationSupport);
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		mixedCase,
		ProtectedClass::ApplicationSupport);

	const auto ignored =
		u"/Users/alice/Library/Application Support/Tele\u200Bgram Desktop/tdata"_q;
	CHECK(policy.Classify(ignored.toUtf8()) == ProtectedClass::ApplicationSupport);

	const auto nfd =
		u"/Users/alice/Library/Application Support/Telegram Desktop/tdata"_q
			.normalized(QString::NormalizationForm_D);
	CHECK(policy.Classify(nfd.toUtf8()) == ProtectedClass::ApplicationSupport);

	auto unicodeFs = FakeFileSystem();
	unicodeFs.entries.emplace(
		"/Users",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	const auto unicodeHome = u"/Users/\u00C9lise"_q;
	unicodeFs.entries.emplace(
		unicodeHome.toUtf8(),
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	const auto unicodePolicy = MacProtectedPathPolicy::Build(
		HomeRoots{
			.accountDatabase = unicodeHome.toUtf8(),
			.foundation = unicodeHome.toUtf8() },
		unicodeFs.operations());
	CHECK(unicodePolicy.valid());
	const auto decomposedHome = unicodeHome.normalized(
		QString::NormalizationForm_D);
	const auto decomposedPath = decomposedHome
		+ u"/Library/Application Support/Telegram Desktop/tdata"_q;
	CHECK(unicodePolicy.Classify(decomposedPath.toUtf8())
		== ProtectedClass::ApplicationSupport);

	const auto firmlink
		= QByteArray("/System/Volumes/Data/Users/alice/Library/Group "
					 "Containers/6N38VWS5BX.ru.keepcoder.Telegram/tdata");
	CHECK(policy.Classify(firmlink) == ProtectedClass::GroupContainer);
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		firmlink,
		ProtectedClass::GroupContainer);
}

TEST_CASE(HomeRootsFromAllSourcesAreProtected) {
	auto fs = FakeFileSystem();
	fs.entries.emplace(
		"/Users",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Users/alice",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Users/bob",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Users/carol",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	const auto policy = MacProtectedPathPolicy::Build(
		HomeRoots{
			.accountDatabase = "/Users/alice",
			.environment = "/Users/bob",
			.foundation = "/Users/carol" },
		fs.operations());
	CHECK(policy.valid());
	CHECK(policy.Classify(
		"/Users/alice/Library/Application Support/Telegram Desktop/x")
		== ProtectedClass::ApplicationSupport);
	CHECK(policy.Classify(
		"/Users/bob/Library/Group Containers/telegram-work/x")
		== ProtectedClass::GroupContainer);
	CHECK(policy.Classify(
		"/Users/carol/Library/Caches/org.telegram.desktop/x")
		== ProtectedClass::BundleKeyed);
}

TEST_CASE(BuildRejectsMissingRequiredHomesWithoutProbing) {
	auto fs = FakeFileSystem();
	for (const auto &path : std::vector<QByteArray>{
			 "/Users",
			 "/Users/alice",
			 "/tmp",
			 "/tmp/h" }) {
		fs.entries.emplace(
			path,
			LstatResult{ .type = FileType::Directory, .error = FileError::None });
	}
	const auto missingRequiredHomes = std::vector<HomeRoots>{
		HomeRoots{
			.environment = "/tmp/h",
			.foundation = "/Users/alice" },
		HomeRoots{
			.accountDatabase = "/Users/alice",
			.environment = "/tmp/h" } };
	for (const auto &homes : missingRequiredHomes) {
		ClearCalls(fs);
		const auto policy = MacProtectedPathPolicy::Build(
			homes,
			fs.operations());
		CHECK(!policy.valid());
		CHECK(fs.lstatCalls.empty());
		CHECK(fs.readlinkCalls.empty());
		CHECK(fs.openCalls.empty());
	}
}

TEST_CASE(BuildRejectsProtectedHomeCandidateWithoutProbing) {
	auto fs = FakeFileSystem();
	const auto directories = std::vector<QByteArray>{
		"/Users",
		"/Users/alice",
		"/Users/alice/Library",
		"/Users/alice/Library/Group Containers" };
	for (const auto &path : directories) {
		fs.entries.emplace(
			path,
			LstatResult{ .type = FileType::Directory, .error = FileError::None });
	}
	const auto protectedRoot = QByteArray(
		"/Users/alice/Library/Group Containers/"
		"6N38VWS5BX.ru.keepcoder.Telegram");
	const auto protectedPrefix = protectedRoot + QByteArray("/");
	auto refusal = RefusalRecord();
	const auto policy = MacProtectedPathPolicy::Build(
		HomeRoots{.accountDatabase = "/Users/alice",
				  .environment = protectedRoot + QByteArray("/tdata"),
				  .foundation = "/Users/alice"},
		fs.operations(), &refusal);
	CHECK(!policy.valid());
	CHECK(refusal.protectedClass == ProtectedClass::GroupContainer);
	for (const auto &call : fs.lstatCalls) {
		CHECK(call != protectedRoot);
		CHECK(!call.startsWith(protectedPrefix));
	}
	for (const auto &call : fs.readlinkCalls) {
		CHECK(call != protectedRoot);
		CHECK(!call.startsWith(protectedPrefix));
	}
	CHECK(fs.openCalls.empty());
}

TEST_CASE(BuildRejectsHomeWithSymlinkDotDotIntoProtectedPath) {
	auto fs = FakeFileSystem();
	const auto directories = std::vector<QByteArray>{
		"/safe",
		"/Users",
		"/Users/alice",
		"/Users/alice/Library",
		"/Users/alice/Library/Group Containers",
		"/safe/child" };
	for (const auto &path : directories) {
		fs.entries.emplace(
			path,
			LstatResult{ .type = FileType::Directory, .error = FileError::None });
	}
	fs.entries.emplace(
		"/safe/link",
		LstatResult{ .type = FileType::Symlink, .error = FileError::None });
	fs.links.emplace(
		"/safe/link",
		ReadlinkResult{
			.target = "/Users/alice/Library/Group Containers/"
				"6N38VWS5BX.ru.keepcoder.Telegram/inner",
			.error = FileError::None });
	const auto protectedRoot = QByteArray(
		"/Users/alice/Library/Group Containers/"
		"6N38VWS5BX.ru.keepcoder.Telegram");
	const auto protectedPrefix = protectedRoot + QByteArray("/");

	const auto policy = MacProtectedPathPolicy::Build(
		HomeRoots{
			.accountDatabase = "/Users/alice",
			.environment = "/safe/link/../child",
			.foundation = "/Users/alice" },
		fs.operations());
	CHECK(!policy.valid());
	CHECK_EQ(int(fs.readlinkCalls.size()), 1);
	CHECK_EQ(fs.readlinkCalls.front(), QByteArray("/safe/link"));
	for (const auto &call : fs.lstatCalls) {
		CHECK(call != protectedRoot);
		CHECK(!call.startsWith(protectedPrefix));
	}
	for (const auto &call : fs.readlinkCalls) {
		CHECK(call != protectedRoot);
		CHECK(!call.startsWith(protectedPrefix));
	}
	CHECK(fs.openCalls.empty());
}

TEST_CASE(RelativeInputsRequireAnAnchorAndResolveAgainstIt) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);

	const auto relative = policy.Resolve(
		Operation::Stat,
		"Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/tdata",
		"/Users/alice", u"unit.relative"_q);
	CHECK(!relative.allowed());
	CHECK(relative.refusal.protectedClass == ProtectedClass::GroupContainer);

	const auto withoutAnchor = policy.Resolve(
		Operation::Stat,
		"Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/tdata", {},
		u"unit.relative.no-anchor"_q);
	CHECK(!withoutAnchor.allowed());
	CHECK(withoutAnchor.refusal.protectedClass == ProtectedClass::Invalid);

	const auto relativeAnchor = policy.Resolve(
		Operation::Stat,
		"Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/tdata",
		"relative/base", u"unit.relative.bad-anchor"_q);
	CHECK(!relativeAnchor.allowed());
	CHECK(relativeAnchor.refusal.protectedClass == ProtectedClass::Invalid);
}

TEST_CASE(InitialWorkingDirectoryAnchorsExternalArguments) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	const auto initialWorkingDirectory
		= QByteArray("/Users/alice/Library/Application Support/Telegramd");

	const auto escapesToTelegramDesktop
		= policy.Resolve(Operation::Open, "../Telegram Desktop/tdata/x",
						 initialWorkingDirectory, u"unit.launcher.argv"_q);
	CHECK(!escapesToTelegramDesktop.allowed());
	CHECK(escapesToTelegramDesktop.refusal.protectedClass
		  == ProtectedClass::ApplicationSupport);
	CHECK(escapesToTelegramDesktop.resolvedPath.isEmpty());
	for (const auto &call : fs.lstatCalls) {
		CHECK(policy.Classify(call) == ProtectedClass::None);
	}
	for (const auto &call : fs.readlinkCalls) {
		CHECK(policy.Classify(call) == ProtectedClass::None);
	}

	ClearCalls(fs);
	const auto allowedUpload
		= policy.Resolve(Operation::Open, "./uploads/x",
						 initialWorkingDirectory, u"unit.launcher.argv"_q);
	CHECK(allowedUpload.allowed());
	CHECK_EQ(
		allowedUpload.resolvedPath,
		QByteArray(
			"/Users/alice/Library/Application Support/Telegramd/uploads/x"));
}

namespace {

[[nodiscard]] auto CheckerFor(MacProtectedPathPolicy &policy) {
	return [&policy](Operation operation, const QString &path,
					 const char *callsite) {
		return policy
			.Resolve(operation, QFile::encodeName(path), {},
					 QString::fromUtf8(callsite))
			.allowed();
	};
}

void WriteFile(const QString &path, const QByteArray &content) {
	auto file = QFile(path);
	CHECK(file.open(QIODevice::WriteOnly));
	CHECK_EQ(file.write(content), content.size());
}

void ReadSettingsExternalPaths(const QByteArray &serialized,
							   Core::SettingsExternalPaths &settings) {
	QDataStream stream(serialized);
	stream.setVersion(QDataStream::Qt_5_1);
	const auto downloadPath
		= Core::SettingsExternalPaths::ReadDownloadPath(stream);
	auto count = qint32();
	stream >> count;
	auto sounds
		= Core::SettingsExternalPaths::ReadSoundOverrides(stream, count);
	CHECK(stream.status() == QDataStream::Ok);
	settings.setDownloadPathFromSerialized(downloadPath);
	settings.restoreSoundOverridesFromSerialized(std::move(sounds));
}

[[nodiscard]] QByteArray
SerializeSettingsExternalPaths(const Core::SettingsExternalPaths &settings) {
	auto result = QByteArray();
	QDataStream stream(&result, QIODevice::WriteOnly);
	stream.setVersion(QDataStream::Qt_5_1);
	settings.serializeDownloadPath(stream);
	settings.serializeSoundOverrides(stream);
	return result;
}

void ReplaceWithProtectedTarget(FakeFileSystem &fs, const QString &parent,
								const QString &replacement,
								const QByteArray &syntheticProtectedTarget) {
	const auto backup = parent + u"-allowed-backup"_q;
	CHECK(QDir().rename(parent, backup));
	CHECK(QFile::link(replacement, parent));
	const auto encoded = QFile::encodeName(parent);
	fs.entries[encoded] = {
		.type = FileType::Symlink,
		.error = FileError::None,
	};
	fs.links[encoded] = {
		.target = syntheticProtectedTarget,
		.error = FileError::None,
	};
}

} // namespace

TEST_CASE(SettingsExternalPathsSurviveAllowedRestartAndRecheckSymlinks) {
	auto temporary = QTemporaryDir();
	CHECK(temporary.isValid());
	const auto parent = temporary.filePath(u"external"_q);
	const auto downloads = parent + u"/downloads"_q;
	const auto sound = parent + u"/notification.mp3"_q;
	const auto replacement
		= temporary.filePath(u"synthetic-protected-fixture"_q);
	CHECK(QDir().mkpath(downloads));
	CHECK(QDir().mkpath(replacement + u"/downloads"_q));
	WriteFile(sound, "allowed sound bytes");
	WriteFile(replacement + u"/notification.mp3"_q,
			  "synthetic protected sound bytes");

	auto fs = FakeFileSystem();
	AddDirectoryHierarchy(fs, QFile::encodeName(temporary.path()));
	AddDirectoryHierarchy(fs, QFile::encodeName(downloads));
	fs.entries.emplace(QFile::encodeName(sound), LstatResult{
													 .type = FileType::Regular,
													 .error = FileError::None,
												 });
	auto policy = TestPolicy(fs);
	auto checker = CheckerFor(policy);
	const auto allowedDownloadPath = downloads;
	const auto allowedSoundPath = sound;
	Core::SettingsExternalPaths original;
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		original.setDownloadPath(allowedDownloadPath);
		original.setSoundOverride(u"notification"_q, allowedSoundPath);
		CHECK_EQ(original.downloadPath(), allowedDownloadPath);
		CHECK_EQ(original.getSoundPath(u"notification"_q), allowedSoundPath);
	}

	const auto serialized = SerializeSettingsExternalPaths(original);
	auto restarted = Core::SettingsExternalPaths();
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		ReadSettingsExternalPaths(serialized, restarted);
		CHECK_EQ(restarted.downloadPath(), allowedDownloadPath);
		CHECK_EQ(restarted.getSoundPath(u"notification"_q), allowedSoundPath);
	}

	const auto protectedTarget = QByteArray(
		"/Users/alice/Library/Containers/org.telegram.desktop/Data/fixture");
	ReplaceWithProtectedTarget(fs, parent, replacement, protectedTarget);
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		CHECK(restarted.downloadPath().isEmpty());
		CHECK_EQ(restarted.getSoundPath(u"notification"_q),
				 u":/sounds/notification.mp3"_q);
		CHECK_EQ(restarted.downloadPathStored(), allowedDownloadPath);
		const auto sound = restarted.soundOverrides().find(u"notification"_q);
		CHECK(sound != restarted.soundOverrides().end());
		if (sound != restarted.soundOverrides().end()) {
			CHECK_EQ(sound->second, allowedSoundPath);
		}
		const auto afterRefusal = SerializeSettingsExternalPaths(restarted);
		auto restartedAgain = Core::SettingsExternalPaths();
		ReadSettingsExternalPaths(afterRefusal, restartedAgain);
		CHECK_EQ(restartedAgain.downloadPathStored(), allowedDownloadPath);
		const auto soundAgain
			= restartedAgain.soundOverrides().find(u"notification"_q);
		CHECK(soundAgain != restartedAgain.soundOverrides().end());
		if (soundAgain != restartedAgain.soundOverrides().end()) {
			CHECK_EQ(soundAgain->second, allowedSoundPath);
		}
		CHECK(restartedAgain.downloadPath().isEmpty());
		CHECK_EQ(restartedAgain.getSoundPath(u"notification"_q),
				 u":/sounds/notification.mp3"_q);
	}
}

TEST_CASE(SettingsExternalPathsPreserveRefusedSerializedValues) {
	auto fs = FakeFileSystem();
	auto policy = TestPolicy(fs);
	auto checker = CheckerFor(policy);
	const auto refused
		= QString::fromUtf8("/Users/alice/Library/Application Support/Telegram "
							"Desktop/tdata/refused");
	auto serialized = QByteArray();
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		auto loaded = Core::SettingsExternalPaths();
		loaded.setDownloadPathFromSerialized(refused);
		auto sounds = base::flat_map<QString, QString>();
		sounds.emplace(u"notification"_q, refused);
		loaded.restoreSoundOverridesFromSerialized(std::move(sounds));
		CHECK(loaded.downloadPath().isEmpty());
		CHECK_EQ(loaded.getSoundPath(u"notification"_q),
				 u":/sounds/notification.mp3"_q);
		CHECK_EQ(loaded.downloadPathStored(), refused);
		const auto sound = loaded.soundOverrides().find(u"notification"_q);
		CHECK(sound != loaded.soundOverrides().end());
		if (sound != loaded.soundOverrides().end()) {
			CHECK_EQ(sound->second, refused);
		}
		serialized = SerializeSettingsExternalPaths(loaded);
	}
	auto restarted = Core::SettingsExternalPaths();
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		ReadSettingsExternalPaths(serialized, restarted);
		CHECK(restarted.downloadPath().isEmpty());
		CHECK_EQ(restarted.downloadPathStored(), refused);
		const auto sound = restarted.soundOverrides().find(u"notification"_q);
		CHECK(sound != restarted.soundOverrides().end());
		if (sound != restarted.soundOverrides().end()) {
			CHECK_EQ(sound->second, refused);
		}
		CHECK_EQ(restarted.getSoundPath(u"notification"_q),
				 u":/sounds/notification.mp3"_q);
		CHECK_EQ(SerializeSettingsExternalPaths(restarted), serialized);
	}
}

TEST_CASE(FileLocationSurvivesRestartAndRefusesReplacedSymlink) {
	auto temporary = QTemporaryDir();
	CHECK(temporary.isValid());
	const auto parent = temporary.filePath(u"media"_q);
	const auto filePath = parent + u"/photo.bin"_q;
	const auto replacement
		= temporary.filePath(u"synthetic-protected-fixture"_q);
	CHECK(QDir().mkpath(parent));
	CHECK(QDir().mkpath(replacement));
	WriteFile(filePath, "allowed media bytes");
	WriteFile(replacement + u"/photo.bin"_q, "synthetic protected media bytes");

	auto fs = FakeFileSystem();
	AddDirectoryHierarchy(fs, QFile::encodeName(temporary.path()));
	fs.entries.emplace(QFile::encodeName(filePath),
					   LstatResult{
						   .type = FileType::Regular,
						   .error = FileError::None,
					   });
	auto policy = TestPolicy(fs);
	auto checker = CheckerFor(policy);
	QString storedPath;
	auto restarted = Core::FileLocation();
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		auto beforeRestart = Core::FileLocation(filePath);
		CHECK_EQ(beforeRestart.name(), filePath);
		storedPath = beforeRestart.serializedName();
	}
	auto serialized = QByteArray();
	{
		QDataStream stream(&serialized, QIODevice::WriteOnly);
		stream << storedPath;
	}
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		auto restartedPath = QString();
		QDataStream stream(serialized);
		stream >> restartedPath;
		restarted = Core::FileLocation(restartedPath);
		CHECK_EQ(restarted.name(), filePath);
		CHECK(restarted.check());
		CHECK_EQ(restarted.serializedName(), filePath);
	}

	ReplaceWithProtectedTarget(
		fs, parent, replacement,
		"/Users/alice/Library/Group Containers/telegramd/fixture");
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		CHECK(restarted.name().isEmpty());
		CHECK(!restarted.check());
		CHECK_EQ(restarted.serializedName(), filePath);
		auto restartedPath = QString();
		QDataStream stream(serialized);
		stream >> restartedPath;
		auto replaced = Core::FileLocation(restartedPath);
		CHECK(replaced.name().isEmpty());
		CHECK(replaced.pathRefused());
		CHECK_EQ(replaced.serializedName(), filePath);
		CHECK_EQ(replaced.fname, filePath);
	}
	auto sentinel = QFile(replacement + u"/photo.bin"_q);
	CHECK(sentinel.open(QIODevice::ReadOnly));
	CHECK_EQ(sentinel.readAll(), QByteArray("synthetic protected media bytes"));
}

TEST_CASE(PersistedThemeRechecksPathAfterRestartAndSymlinkReplacement) {
	auto temporary = QTemporaryDir();
	CHECK(temporary.isValid());
	const auto parent = temporary.filePath(u"themes"_q);
	const auto themePath = parent + u"/theme.tdesktop-theme"_q;
	const auto replacement
		= temporary.filePath(u"synthetic-protected-fixture"_q);
	CHECK(QDir().mkpath(parent));
	CHECK(QDir().mkpath(replacement));
	WriteFile(themePath, "allowed theme bytes");
	WriteFile(replacement + u"/theme.tdesktop-theme"_q,
			  "synthetic protected theme bytes");

	auto fs = FakeFileSystem();
	AddDirectoryHierarchy(fs, QFile::encodeName(temporary.path()));
	fs.entries.emplace(QFile::encodeName(themePath),
					   LstatResult{
						   .type = FileType::Regular,
						   .error = FileError::None,
					   });
	auto policy = TestPolicy(fs);
	auto checker = CheckerFor(policy);
	auto serialized = QByteArray();
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		auto original = Window::Theme::Object();
		original.content = "serialized theme bytes";
		original.pathAbsolute = themePath;
		auto stream = QDataStream(&serialized, QIODevice::WriteOnly);
		stream.setVersion(QDataStream::Qt_5_1);
		stream << original.content << QStringLiteral("special://new_tag")
			   << original.pathAbsolute << original.pathRelative
			   << original.cloud.id << original.cloud.accessHash
			   << original.cloud.slug << original.cloud.title
			   << original.cloud.documentId << qint32(0);
	}
	const auto loadAfterRestart = [&] {
		auto restored = Window::Theme::Object();
		auto tag = QString();
		auto field1 = qint32();
		QDataStream stream(serialized);
		stream.setVersion(QDataStream::Qt_5_1);
		stream >> restored.content >> tag >> restored.pathAbsolute;
		if (tag == QStringLiteral("special://new_tag")) {
			stream >> restored.pathRelative >> restored.cloud.id
				>> restored.cloud.accessHash >> restored.cloud.slug
				>> restored.cloud.title >> restored.cloud.documentId >> field1;
		} else {
			restored.pathRelative = tag;
		}
		CHECK(stream.status() == QDataStream::Ok);
		return Storage::details::LoadThemeFileContent(restored);
	};
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		const auto loaded = loadAfterRestart();
		CHECK(!loaded.refusedPath);
		CHECK(loaded.contentChanged);
	}

	ReplaceWithProtectedTarget(
		fs, parent, replacement,
		"/Users/alice/Library/Application Support/Telegram Desktop/themes");
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		const auto refused = loadAfterRestart();
		CHECK(refused.refusedPath);
		CHECK(!refused.contentChanged);
	}
	auto sentinel = QFile(replacement + u"/theme.tdesktop-theme"_q);
	CHECK(sentinel.open(QIODevice::ReadOnly));
	CHECK_EQ(sentinel.readAll(), QByteArray("synthetic protected theme bytes"));
}

TEST_CASE(CancelledDownloadDoesNotUnlinkReplacedProtectedTarget) {
	auto temporary = QTemporaryDir();
	CHECK(temporary.isValid());
	const auto parent = temporary.filePath(u"download"_q);
	const auto destination = parent + u"/partial.bin"_q;
	const auto replacement
		= temporary.filePath(u"synthetic-protected-fixture"_q);
	CHECK(QDir().mkpath(parent));
	CHECK(QDir().mkpath(replacement));
	WriteFile(replacement + u"/partial.bin"_q, "synthetic protected target");

	auto fs = FakeFileSystem();
	AddDirectoryHierarchy(fs, QFile::encodeName(temporary.path()));
	AddDirectoryHierarchy(fs, QFile::encodeName(parent));
	fs.entries[QFile::encodeName(destination)] = {
		.type = FileType::Regular,
		.error = FileError::None,
	};
	auto policy = TestPolicy(fs);
	auto checker = CheckerFor(policy);
	auto output = QFile(destination);
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		CHECK(OpenExternalFile(output, QIODevice::WriteOnly, Operation::Write,
							   "file-loader.output-open"));
		const auto partial = QByteArray("partial download bytes");
		CHECK_EQ(output.write(partial), partial.size());
	}
	output.close();
	ReplaceWithProtectedTarget(
		fs, parent, replacement,
		"/Users/alice/Library/Application Support/Telegram Desktop/downloads");
	{
		ScopedExternalPathCheckerForTesting scope(checker);
		CHECK(!RemoveExternalFile(output, "file-loader.cancel-remove"));
	}
	auto sentinel = QFile(replacement + u"/partial.bin"_q);
	CHECK(sentinel.open(QIODevice::ReadOnly));
	CHECK_EQ(sentinel.readAll(), QByteArray("synthetic protected target"));
}

TEST_CASE(QueuedUploadAndCacheDownloadRecheckPathsBeforeOpen) {
	auto temporary = QTemporaryDir();
	CHECK(temporary.isValid());
	const auto write = [](const QString &path, const QByteArray &content) {
		auto file = QFile(path);
		return file.open(QIODevice::WriteOnly)
			   && file.write(content) == content.size();
	};
	const auto safeTarget = temporary.filePath(u"safe-target"_q);
	const auto uploadPath = temporary.filePath(u"queued-upload"_q);
	const auto downloadPath = temporary.filePath(u"cache-download"_q);
	CHECK(write(safeTarget, "synthetic safe bytes"));
	CHECK(write(uploadPath, "prepared upload bytes"));
	CHECK(write(downloadPath, "prepared download bytes"));
	auto fs = FakeFileSystem();
	AddDirectoryHierarchy(fs, QFile::encodeName(temporary.path()));
	for (const auto &path : {uploadPath, downloadPath}) {
		fs.entries.emplace(
			QFile::encodeName(path),
			LstatResult{.type = FileType::Regular, .error = FileError::None});
	}
	const auto policy = TestPolicy(fs);
	const auto check
		= [&](Operation operation, const QString &path, const char *callsite) {
			  return policy
				  .Resolve(operation, QFile::encodeName(path), {},
						   QString::fromUtf8(callsite))
				  .allowed();
		  };
	const auto protectedTarget
		= u"/Users/alice/Library/Application Support/Telegram Desktop/tdata/synthetic"_q;
	CHECK(PersistedExternalPath(uploadPath)
			  .allowed(Operation::Read, "file-upload.source-open", check));
	CHECK(PersistedExternalPath(downloadPath)
			  .allowed(Operation::Write, "file-loader.output-open", check));
	for (const auto &path : {uploadPath, downloadPath}) {
		CHECK(QFile::remove(path));
		if (!QFile::link(safeTarget, path)) {
			CHECK(false);
			return;
		}
		const auto encoded = QFile::encodeName(path);
		fs.entries[encoded] = {
			.type = FileType::Symlink,
			.error = FileError::None,
		};
		fs.links[encoded] = {
			.target = QFile::encodeName(protectedTarget),
			.error = FileError::None,
		};
	}
	auto upload = QFile(uploadPath);
	CHECK(!OpenExternalFile(upload, QIODevice::ReadOnly, Operation::Read,
							"file-upload.source-open", check));
	CHECK(!upload.isOpen());
	auto download = QFile(downloadPath);
	CHECK(!OpenExternalFile(download, QIODevice::WriteOnly, Operation::Write,
							"file-loader.output-open", check));
	CHECK(!download.isOpen());
	auto safe = QFile(safeTarget);
	CHECK(safe.open(QIODevice::ReadOnly));
	CHECK_EQ(safe.readAll(), QByteArray("synthetic safe bytes"));
}

TEST_CASE(DotSegmentsAreResolvedBeforeFilesystemProbes) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	for (const auto &directory : std::vector<QByteArray>{
			 "/Users/alice/Library", "/Users/alice/Library/Application Support",
			 "/Users/alice/Library/Application Support/Teagram",
			 "/Users/alice/Library/Application Support/Teagram/tdata"}) {
		fs.entries[directory] = LstatResult{
			.type = FileType::Directory,
			.error = FileError::None };
	}
	const auto path
		= QByteArray("//Users/alice/./Library/Application Support/Teagram/../"
					 "Telegram Desktop/tdata");
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		path,
		ProtectedClass::ApplicationSupport);

	ClearCalls(fs);
	const auto allowed = policy.Resolve(
		Operation::Open,
		"/Users/alice/Library/Application Support/Teagram/./tdata/../x", {},
		u"unit.dot.allowed"_q);
	CHECK(allowed.allowed());
	CHECK_EQ(allowed.resolvedPath,
			 QByteArray("/Users/alice/Library/Application Support/Teagram/x"));
}

TEST_CASE(DotDotAfterMissingComponentFailsClosed) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	fs.entries["/safe"] =
		LstatResult{ .type = FileType::Directory, .error = FileError::None };
	fs.entries["/safe/link"] =
		LstatResult{ .type = FileType::Symlink, .error = FileError::None };
	fs.links["/safe/link"] = ReadlinkResult{
		.target = "/Users/alice/Library/Group "
				  "Containers/6N38VWS5BX.ru.keepcoder.Telegram",
		.error = FileError::None};

	ClearCalls(fs);
	const auto result = policy.Resolve(
		Operation::Open,
		"/safe/missing/../link/tdata",
		{},
		u"unit.missing-parent"_q);
	CHECK(!result.allowed());
	CHECK(result.refusal.protectedClass == ProtectedClass::Invalid);
	CHECK_EQ(int(fs.lstatCalls.size()), 2);
	CHECK_EQ(fs.lstatCalls[0], QByteArray("/safe"));
	CHECK_EQ(fs.lstatCalls[1], QByteArray("/safe/missing"));
	CHECK(fs.readlinkCalls.empty());
	CHECK(fs.openCalls.empty());
}

TEST_CASE(SymlinkTargetsAreSplicedPhysically) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	fs.entries.emplace(
		"/safe",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/safe/link",
		LstatResult{ .type = FileType::Symlink, .error = FileError::None });
	fs.links.emplace(
		"/safe/link",
		ReadlinkResult{
			.target = "/Users/alice/Library/Application Support/Telegram Desktop",
			.error = FileError::None });
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		"/safe/link/tdata",
		ProtectedClass::ApplicationSupport);

	ClearCalls(fs);
	fs.entries["/safe/relative"] =
		LstatResult{ .type = FileType::Symlink, .error = FileError::None };
	fs.links["/safe/relative"] = ReadlinkResult{
		.target = "../Users/alice/Library/Group "
				  "Containers/6N38VWS5BX.ru.keepcoder.Telegram",
		.error = FileError::None};
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		"/safe/relative/tdata",
		ProtectedClass::GroupContainer);

	ClearCalls(fs);
	fs.entries["/safe/dangling"] =
		LstatResult{ .type = FileType::Symlink, .error = FileError::None };
	fs.links["/safe/dangling"] = ReadlinkResult{
		.target = "/Users/alice/Library/Containers/org.telegram.desktop",
		.error = FileError::None };
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		"/safe/dangling/tdata",
		ProtectedClass::Container);
}

TEST_CASE(FinalSymlinkOperationsKeepNoFollowSemantics) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	fs.entries.emplace("/safe", LstatResult{.type = FileType::Directory,
											.error = FileError::None});
	fs.entries.emplace("/safe/link", LstatResult{.type = FileType::Symlink,
												 .error = FileError::None});
	fs.links.emplace(
		"/safe/link",
		ReadlinkResult{
			.target
			= "/Users/alice/Library/Application Support/Telegram Desktop",
			.error = FileError::None});

	for (const auto operation :
		 {Operation::Lstat, Operation::Unlink, Operation::Rename}) {
		ClearCalls(fs);
		const auto result = policy.Resolve(operation, "/safe/link", {},
										   u"unit.final-symlink"_q);
		CHECK(result.allowed());
		CHECK_EQ(result.resolvedPath, QByteArray("/safe/link"));
		CHECK(fs.readlinkCalls.empty());
	}
	ClearCalls(fs);
	const auto recursiveDelete
		= policy.Resolve(Operation::RecursiveDelete, "/safe/link", {},
						 u"unit.recursive-delete-root-symlink"_q);
	CHECK(!recursiveDelete.allowed());
	CHECK(recursiveDelete.refusal.protectedClass
		  == ProtectedClass::ApplicationSupport);
	CHECK(fs.readlinkCalls == std::vector<QByteArray>{"/safe/link"});

	ClearCalls(fs);
	const auto followed = policy.Resolve(Operation::Open, "/safe/link", {},
										 u"unit.followed-symlink"_q);
	CHECK(!followed.allowed());
	CHECK(fs.readlinkCalls == std::vector<QByteArray>{"/safe/link"});
}

TEST_CASE(RecursiveDeleteLeavesProtectedChildSymlinkTarget) {
	auto home = QTemporaryDir();
	CHECK(home.isValid());
	if (!home.isValid()) {
		return;
	}
	const auto homePath = home.path();
	const auto profilePath = homePath + u"/profile"_q;
	const auto protectedPath
		= homePath + u"/Library/Application Support/Telegram Desktop"_q;
	const auto markerPath = protectedPath + u"/keep.txt"_q;
	CHECK(QDir().mkpath(profilePath));
	CHECK(QDir().mkpath(protectedPath));
	auto marker = QFile(markerPath);
	CHECK(marker.open(QIODevice::WriteOnly));
	CHECK_EQ(marker.write("keep"), 4);
	marker.close();
	const auto linkPath = profilePath + u"/official"_q;
	CHECK(QFile::link(protectedPath, linkPath));
	CHECK(QFileInfo(linkPath).isSymLink());

	auto fs = FakeFileSystem();
	AddDirectoryHierarchy(fs, QFile::encodeName(homePath));
	AddDirectoryHierarchy(fs, QFile::encodeName(profilePath));
	const auto policy = MacProtectedPathPolicy::Build(
		HomeRoots{.accountDatabase = QFile::encodeName(homePath),
				  .foundation = QFile::encodeName(homePath)},
		fs.operations());
	CHECK(policy.valid());
	CHECK(policy
			  .Resolve(Operation::RecursiveDelete,
					   QFile::encodeName(profilePath),
					   QFile::encodeName(homePath),
					   u"unit.recursive-delete-child-symlink"_q)
			  .allowed());
	CHECK(QDir(profilePath).removeRecursively());
	CHECK(QFileInfo::exists(markerPath));
}

TEST_CASE(SymlinkHopLimitAndFilesystemErrorsFailClosed) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	fs.entries.emplace(
		"/safe",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	for (auto i = 0; i != 32; ++i) {
		const auto name = QByteArray("/safe/link") + QByteArray::number(i);
		const auto target = (i == 31)
			? QByteArray("/safe/target")
			: QByteArray("/safe/link") + QByteArray::number(i + 1);
		fs.entries[name] =
			LstatResult{ .type = FileType::Symlink, .error = FileError::None };
		fs.links[name] = ReadlinkResult{
			.target = target,
			.error = FileError::None };
	}
	fs.entries.emplace(
		"/safe/target",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	const auto chain = policy.Resolve(
		Operation::Open,
		"/safe/link0/tdata",
		{},
		u"unit.chain"_q);
	CHECK(chain.allowed());

	for (auto i = 0; i != 32; ++i) {
		const auto name = QByteArray("/safe/loop") + QByteArray::number(i);
		const auto target = (i == 31)
			? QByteArray("/safe/loop0")
			: QByteArray("/safe/loop") + QByteArray::number(i + 1);
		fs.entries[name] =
			LstatResult{ .type = FileType::Symlink, .error = FileError::None };
		fs.links[name] = ReadlinkResult{
			.target = target,
			.error = FileError::None };
	}
	const auto loop = policy.Resolve(
		Operation::Open,
		"/safe/loop0/tdata",
		{},
		u"unit.loop"_q);
	CHECK(!loop.allowed());
	CHECK(loop.refusal.protectedClass == ProtectedClass::Invalid);

	fs.entries["/broken"] =
		LstatResult{ .error = FileError::Unexpected };
	const auto unexpected = policy.Resolve(
		Operation::Open,
		"/broken/path",
		{},
		u"unit.error"_q);
	CHECK(!unexpected.allowed());
	CHECK(unexpected.refusal.protectedClass == ProtectedClass::Invalid);

	fs.entries["/ambiguous"] =
		LstatResult{ .error = FileError::Ambiguous };
	const auto ambiguous = policy.Resolve(
		Operation::Open,
		"/ambiguous/path",
		{},
		u"unit.ambiguous"_q);
	CHECK(!ambiguous.allowed());
	CHECK(ambiguous.refusal.protectedClass == ProtectedClass::Invalid);
}

TEST_CASE(RealpathHomeAliasesAndFirmlinksShareTheBoundary) {
	auto fs = FakeFileSystem();
	fs.entries.emplace(
		"/Aliases",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Aliases/alice",
		LstatResult{ .type = FileType::Symlink, .error = FileError::None });
	fs.links.emplace(
		"/Aliases/alice",
		ReadlinkResult{
			.target = "/Users/alice",
			.error = FileError::None });
	fs.entries.emplace(
		"/Users",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Users/alice",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	const auto policy = MacProtectedPathPolicy::Build(
		HomeRoots{
			.accountDatabase = "/Aliases/alice",
			.foundation = "/Aliases/alice" },
		fs.operations());
	CHECK(policy.valid());

	const auto canonical = QByteArray(
		"/Users/alice/Library/Application Support/Telegram Desktop/x");
	const auto alias = QByteArray(
		"/Aliases/alice/Library/Application Support/Telegram Desktop/x");
	const auto firmlink = QByteArray(
		"/System/Volumes/Data/Users/alice/Library/Application Support/Telegram Desktop/x");
	CHECK(policy.Classify(canonical) == ProtectedClass::ApplicationSupport);
	CHECK(policy.Classify(alias) == ProtectedClass::ApplicationSupport);
	CHECK(policy.Classify(firmlink) == ProtectedClass::ApplicationSupport);
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		canonical,
		ProtectedClass::ApplicationSupport);
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		alias,
		ProtectedClass::ApplicationSupport);
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		firmlink,
		ProtectedClass::ApplicationSupport);
}

TEST_CASE(InvalidNamesAndMissingHomesFailClosed) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	const auto invalid = QByteArray("/safe/")
		+ QByteArray::fromHex("ff")
		+ "/path";
	ClearCalls(fs);
	const auto invalidResult = policy.Resolve(
		Operation::Open,
		invalid,
		{},
		u"unit.invalid-name"_q);
	CHECK(!invalidResult.allowed());
	CHECK(invalidResult.refusal.protectedClass == ProtectedClass::Invalid);
	CHECK(fs.lstatCalls.empty());
	CHECK(fs.readlinkCalls.empty());

	fs.entries["/safe"] =
		LstatResult{ .type = FileType::Directory, .error = FileError::None };
	fs.entries["/safe/link"] =
		LstatResult{ .type = FileType::Symlink, .error = FileError::None };
	fs.links["/safe/link"] = ReadlinkResult{
		.target = QByteArray::fromHex("ff"),
		.error = FileError::None };
	const auto invalidTarget = policy.Resolve(
		Operation::Open,
		"/safe/link/path",
		{},
		u"unit.invalid-target"_q);
	CHECK(!invalidTarget.allowed());
	CHECK(invalidTarget.refusal.protectedClass == ProtectedClass::Invalid);

	auto missingHomeFs = FakeFileSystem();
	const auto missingHome = MacProtectedPathPolicy::Build(
		HomeRoots{
			.accountDatabase = "/Users/alice",
			.foundation = "/Users/alice" },
		missingHomeFs.operations());
	CHECK(!missingHome.valid());
	const auto missingResult = missingHome.Resolve(
		Operation::Open,
		"/Users/alice/Library/Application Support/Telegram Desktop/x",
		{},
		u"unit.missing-home"_q);
	CHECK(!missingResult.allowed());
	CHECK(missingResult.refusal.protectedClass == ProtectedClass::Invalid);
}

TEST_CASE(RefusalRecordsAreRateLimitedWithoutPaths) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	auto now = qint64(100);
	auto log = RefusalLog([&] { return now; });

	const auto first
		= policy.Resolve(Operation::Open,
						 "/Users/alice/Library/Group "
						 "Containers/6N38VWS5BX.ru.keepcoder.Telegram/x",
						 {}, u"unit.first"_q, &log);
	const auto second
		= policy.Resolve(Operation::Open,
						 "/Users/alice/Library/Group "
						 "Containers/6N38VWS5BX.ru.keepcoder.Telegram/y",
						 {}, u"unit.second"_q, &log);
	CHECK(!first.allowed());
	CHECK(!second.allowed());
	CHECK_EQ(int(log.records().size()), 1);
	CHECK_EQ(log.records().front().callsite, u"unit.first"_q);

	now = 160;
	const auto third
		= policy.Resolve(Operation::Open,
						 "/Users/alice/Library/Group "
						 "Containers/6N38VWS5BX.ru.keepcoder.Telegram/z",
						 {}, u"unit.third"_q, &log);
	CHECK(!third.allowed());
	CHECK_EQ(int(log.records().size()), 2);
	CHECK_EQ(log.records().back().callsite, u"unit.third"_q);
}

TEST_CASE(OperationAndPairChecksCoverBothEndpoints) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	const auto protectedPath = QByteArray(
		"/Users/alice/Library/Application Support/Telegram Desktop/x");
	const auto operations = std::vector<Operation>{
		Operation::Open,
		Operation::Read,
		Operation::Write,
		Operation::Stat,
		Operation::Lstat,
		Operation::OpenDir,
		Operation::GetAttrList,
		Operation::Mkdir,
		Operation::Lock,
		Operation::Rename,
		Operation::Copy,
		Operation::Link,
		Operation::Unlink,
		Operation::Rmdir,
		Operation::RecursiveDelete,
	};
	for (const auto operation : operations) {
		const auto result = policy.Resolve(
			operation,
			protectedPath,
			{},
			u"unit.operation"_q);
		CHECK(!result.allowed());
		CHECK(result.refusal.operation == operation);
	}

	const auto pair = policy.ResolvePair(
		Operation::Rename,
		"/safe/source",
		protectedPath,
		{},
		u"unit.pair"_q);
	CHECK(pair.first.allowed());
	CHECK(!pair.second.allowed());
	CHECK(pair.second.refusal.protectedClass == ProtectedClass::ApplicationSupport);
	const auto reversedPair = policy.ResolvePair(
		Operation::Copy,
		protectedPath,
		"/safe/destination",
		{},
		u"unit.reversed-pair"_q);
	CHECK(!reversedPair.first.allowed());
	CHECK(reversedPair.second.allowed());
	CHECK(reversedPair.first.refusal.protectedClass
		== ProtectedClass::ApplicationSupport);
	for (const auto &call : fs.lstatCalls) {
		CHECK(policy.Classify(call) == ProtectedClass::None);
	}
}

TEST_CASE(DestructiveOperationsRefuseProtectedAncestors) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	CHECK(policy.valid());
	const auto ancestors = std::vector<QByteArray>{
		"/",
		"/Users",
		"/Users/alice",
		"/Users/alice/Library",
		"/Users/alice/Library/Application Support",
		"/Users/alice/Library/Containers",
		"/Users/alice/Library/Group Containers",
		"/Users/alice/Library/Preferences",
		"/Users/alice/Library/Caches",
		"/Users/alice/Library/HTTPStorages",
		"/Users/alice/Library/WebKit",
		"/Users/alice/Library/Saved Application State",
		"/System/Volumes/Data/Users/alice/Library/Group Containers" };
	const auto destructive = std::vector<Operation>{
		Operation::Rename,
		Operation::Link,
		Operation::Unlink,
		Operation::Rmdir,
		Operation::RecursiveDelete };
	for (const auto operation : destructive) {
		for (const auto &path : ancestors) {
			ClearCalls(fs);
			const auto result = policy.Resolve(
				operation,
				path,
				{},
				u"unit.ancestor"_q);
			CHECK(!result.allowed());
			CHECK(result.refusal.protectedClass != ProtectedClass::None);
			CHECK(fs.openCalls.empty());
			for (const auto &call : fs.lstatCalls) {
				CHECK(call != path);
				CHECK(policy.Classify(call) == ProtectedClass::None);
			}
			for (const auto &call : fs.readlinkCalls) {
				CHECK(policy.Classify(call) == ProtectedClass::None);
			}
		}
	}
	const auto allowed
		= QByteArray("/Users/alice/Library/Application Support/Teagram/x");
	CHECK(policy.Resolve(
		Operation::Open,
		"/Users/alice/Library/Group Containers",
		{},
		u"unit.ancestor.read"_q).allowed());
	fs.entries.emplace(
		"/safe",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/safe/link",
		LstatResult{ .type = FileType::Symlink, .error = FileError::None });
	fs.links.emplace(
		"/safe/link",
		ReadlinkResult{
			.target = "/Users/alice/Library/Group Containers",
			.error = FileError::None });
	ClearCalls(fs);
	CHECK(policy
			  .Resolve(Operation::Rename, "/safe/link", {},
					   u"unit.ancestor.alias"_q)
			  .allowed());
	CHECK(fs.readlinkCalls.empty());
	const auto aliasChild
		= policy.Resolve(Operation::Rename, "/safe/link/entry", {},
						 u"unit.ancestor.alias-parent"_q);
	CHECK(!aliasChild.allowed());
	CHECK(aliasChild.refusal.protectedClass == ProtectedClass::GroupContainer);
	for (const auto &call : fs.lstatCalls) {
		CHECK(call != QByteArray("/Users/alice/Library/Group Containers"));
	}
	CHECK(policy.Resolve(
		Operation::Rename,
		allowed,
		{},
		u"unit.ancestor.allowed"_q).allowed());
	const auto source = QByteArray("/safe/source");
	CHECK(!policy.ResolvePair(
		Operation::Rename,
		"/Users/alice/Library/Group Containers",
		source,
		{},
		u"unit.ancestor.first"_q).allowed());
	CHECK(!policy.ResolvePair(
		Operation::Rename,
		source,
		"/Users/alice/Library/Group Containers",
		{},
		u"unit.ancestor.second"_q).allowed());
}
