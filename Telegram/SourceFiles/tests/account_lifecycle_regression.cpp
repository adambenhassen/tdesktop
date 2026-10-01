/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/account_lifecycle_regression.h"

#include "apiwrap.h"
#include "core/application.h"
#include "core/launcher.h"
#include "crl/crl_on_main.h"
#include "data/data_chat.h"
#include "data/data_peer_id.h"
#include "data/data_session.h"
#include "data/data_user.h"
#include "main/main_account.h"
#include "main/main_account_persistence.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "main/main_session_settings.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/mtproto_auth_key.h"
#include "mtproto/mtproto_config.h"
#include "mtproto/sender.h"
#include "storage/details/storage_file_utilities.h"
#include "storage/storage_account.h"
#include "storage/storage_domain.h"
#include "storage/storage_encryption.h"
#include "settings.h"

#include <QtCore/QByteArray>
#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QEventLoop>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QMetaObject>
#include <QtCore/QStringList>
#include <QtCore/QTimer>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QTcpSocket>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <memory>
#include <optional>
#include <thread>

namespace Tests {
#ifdef TDESKTOP_LIFECYCLE_REGRESSION
namespace {

constexpr auto kAuthStartupRegressionVariable =
	"TDESKTOP_AUTH_STARTUP_REGRESSION";
constexpr auto kAuthStartupRegressionRootVariable =
	"TDESKTOP_AUTH_STARTUP_REGRESSION_ROOT";
constexpr auto kAuthStartupFailPrepareVariable =
	"TDESKTOP_AUTH_STARTUP_REGRESSION_FAIL_PREPARE";
constexpr auto kAuthStartupForbiddenOutboundVariable =
	"TDESKTOP_AUTH_STARTUP_REGRESSION_FORBIDDEN_OUTBOUND";
constexpr auto kAuthStartupRegressionMarker =
	"tdesktop-auth-startup-regression-v1";
constexpr auto kAuthStartupObservationWindowMs = 1500;
constexpr auto kAuthStartupForbiddenOutboundDelayMs = 250;
constexpr auto kAuthStartupOldUserId = UserId(4242);
constexpr auto kAuthStartupNewUserId = UserId(5252);

struct AuthStartupRegressionRequest final {
	bool prepare = false;
	QString name;
	int forgetPoint = 0;
};

[[nodiscard]] std::shared_ptr<MTP::details::RSAPublicKey>
RegressionServerKey();
[[nodiscard]] MTP::AuthKeyPtr RegressionAuthKey(int byte);
[[nodiscard]] bool ConfigurePinnedServer(
		not_null<Main::Account*> account,
		std::shared_ptr<MTP::details::RSAPublicKey> key);
[[nodiscard]] bool HasAuthKey(
		not_null<Main::Account*> account,
		MTP::AuthKey::KeyId keyId);
[[nodiscard]] bool HasNoAuthorizationState(
		not_null<Main::Account*> account);

auto gLifecycleWriteCounts = LifecycleWriteCountsForRegressionTest();
auto gAuthStartupState = AuthStartupStateForRegressionTest();
auto gAuthStartupForbiddenOutboundAttempt = false;
std::unique_ptr<QTcpSocket> gAuthStartupForbiddenSocket;

[[nodiscard]] std::optional<AuthStartupRegressionRequest>
ParseAuthStartupRegressionRequest() {
	const auto parts = qEnvironmentVariable(
		kAuthStartupRegressionVariable).split(':');
	if ((parts.size() != 2)
		|| ((parts.front() != u"prepare"_q)
			&& (parts.front() != u"verify"_q))) {
		return std::nullopt;
	}
	const auto name = parts.back();
	if ((name == u"missing-pin"_q)
		|| (name == u"incomplete-pin"_q)
		|| (name == u"unreadable-config"_q)
		|| (name == u"unreadable-pin"_q)) {
		return AuthStartupRegressionRequest{
			.prepare = (parts.front() == u"prepare"_q),
			.name = name,
		};
	}
	if (name.startsWith(u"forget-"_q)) {
		bool ok = false;
		const auto point = name.mid(7).toInt(&ok);
		if (ok && (point >= 1) && (point <= 6)) {
			return AuthStartupRegressionRequest{
				.prepare = (parts.front() == u"prepare"_q),
				.name = name,
				.forgetPoint = point,
			};
		}
	}
	return std::nullopt;
}

[[nodiscard]] bool IsUnderPath(
		const QString &path,
		const QString &parent) {
	return path.startsWith(parent + QDir::separator());
}

void FailAuthStartupRegression(
		const QString &name,
		const char *reason) {
	std::fprintf(
		stderr,
		"Auth startup regression failed: case=%s: %s\n",
		name.toUtf8().constData(),
		reason);
}

[[nodiscard]] QString AuthStartupConfigPath() {
	const auto root = QDir(cWorkingDir() + u"tdata"_q);
	const auto names = QStringList{
		u"config"_q,
		u"configs"_q,
		u"config0"_q,
		u"config1"_q,
	};
	auto result = QString();
	for (const auto &directory : root.entryList(
			QDir::Dirs | QDir::NoDotAndDotDot)) {
		const auto path = root.filePath(directory);
		const auto hasConfig = std::any_of(
			names.begin(),
			names.end(),
			[&](const QString &name) {
				return QFileInfo::exists(
					path + QDir::separator() + name);
			});
		if (hasConfig) {
			if (!result.isEmpty()) {
				return QString();
			}
			result = path + QDir::separator() + u"config"_q;
		}
	}
	return result;
}

[[nodiscard]] bool RemoveAuthStartupConfig() {
	const auto path = AuthStartupConfigPath();
	if (path.isEmpty()) {
		return false;
	}
	auto removed = false;
	for (const auto &suffix : {
			QString(),
			u"s"_q,
			u"0"_q,
			u"1"_q,
		}) {
		const auto file = path + suffix;
		if (QFileInfo::exists(file)) {
			if (!QFile::remove(file)) {
				return false;
			}
			removed = true;
		}
	}
	return removed;
}

[[nodiscard]] bool PrepareAuthStartupRegression(
		const AuthStartupRegressionRequest &request) {
	auto &domain = Core::App().domain();
	if (!domain.started() || (domain.accounts().size() != 1)) {
		FailAuthStartupRegression(
			request.name,
			"fixture preparation needs one fresh account");
		return false;
	}
	const auto account = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (account->sessionExists()
		|| !HasNoAuthorizationState(account)
		|| account->local().hasStoredCustomServer()
		|| account->local().customServerPinUnknown()
		|| account->local().mtpAuthorizationWriteFailed()
		|| account->local().serverForgetPending()
		|| account->local().mtpAuthorizationDataExistsForRegressionTest()
		|| !account->mtp().dcOptions().unenrolled()) {
		FailAuthStartupRegression(
			request.name,
			"fixture workdir is not fresh; create a new disposable root");
		return false;
	}
	account->mtp().stopForServerEnrollment();
	const auto oldKey = RegressionAuthKey(0x51);
	const auto oldKeyId = oldKey->keyId();
	if (!oldKeyId) {
		FailAuthStartupRegression(
			request.name,
			"synthetic authorization key has an invalid id");
		return false;
	}
	if (request.forgetPoint) {
		if (!ConfigurePinnedServer(account, RegressionServerKey())) {
			FailAuthStartupRegression(
				request.name,
				"could not store the synthetic server pin");
			return false;
		}
	}
	account->setSessionUserId(kAuthStartupOldUserId);
	account->mtp().dcPersistentKeyChanged(2, oldKey);
	if (!HasAuthKey(account, oldKeyId)) {
		FailAuthStartupRegression(
			request.name,
			"could not seed the stale synthetic authorization key");
		return false;
	}
	if (!account->local().writeMtpAuthorization()
		|| !account->local().mtpAuthorizationDataExistsForRegressionTest()
		|| !HasAuthKey(account, oldKeyId)) {
		FailAuthStartupRegression(
			request.name,
			"could not persist the stale synthetic authorization");
		return false;
	}
	domain.local().writeAccounts();
	if (request.name == u"incomplete-pin"_q) {
		account->local().writeCustomServerBlocked(false);
		if (!account->local()
			.flushAndVerifyPinPrefsForRegressionTest(true)) {
			FailAuthStartupRegression(
				request.name,
				"the persisted account map did not reload its pinned prefs linkage");
			return false;
		}
	} else if (request.name == u"unreadable-config"_q) {
		account->local().writeCustomServerBlocked(false);
		if (!account->local()
			.flushAndVerifyPinPrefsForRegressionTest(true)) {
			FailAuthStartupRegression(
				request.name,
				"the persisted account map did not reload its pinned prefs linkage");
			return false;
		}
		if (!RemoveAuthStartupConfig()) {
			FailAuthStartupRegression(
				request.name,
				"could not remove the disposable config variants");
			return false;
		}
	} else if (request.name == u"unreadable-pin"_q) {
		account->local().writeCustomServerBlocked(false);
		if (!account->local()
			.flushAndVerifyPinPrefsForRegressionTest(true)) {
			FailAuthStartupRegression(
				request.name,
				"the persisted account map did not reload its pinned prefs linkage");
			return false;
		}
		if (!account->local().removePrefsForRegressionTest()) {
			FailAuthStartupRegression(
				request.name,
				"could not remove the disposable pin preferences");
			return false;
		}
	} else if (request.forgetPoint) {
		const auto binding = Storage::ServerCacheBinding{
			.fingerprintKnown = true,
			.fingerprint = RegressionServerKey()->fingerprint(),
			.userIdKnown = true,
			.userId = kAuthStartupOldUserId.bare,
		};
		if (!account->local()
			.flushAndVerifyPinPrefsForRegressionTest(true)) {
			FailAuthStartupRegression(
				request.name,
				"the persisted account map did not reload its pinned prefs linkage");
			return false;
		}
		account->local().setServerForgetInterruptionForTest(
			request.forgetPoint);
		if (account->local().beginServerForget(binding)
			|| !account->local().serverForgetPending()) {
			FailAuthStartupRegression(
				request.name,
				"Forget did not stop at the requested durable boundary");
			return false;
		}
	} else if (request.name != u"missing-pin"_q) {
		FailAuthStartupRegression(
			request.name,
			"unsupported fixture case");
		return false;
	} else if (!account->local()
		.flushAndVerifyPinPrefsForRegressionTest(false)) {
		FailAuthStartupRegression(
			request.name,
			"the persisted account map did not reload the expected absent pin prefs");
		return false;
	}
	Storage::details::Sync();
	if (qEnvironmentVariable(kAuthStartupFailPrepareVariable)
		== request.name) {
		FailAuthStartupRegression(
			request.name,
			"sensitivity injection: prepare failed after the fixture was verified");
		return false;
	}
	return true;
}

[[nodiscard]] bool VerifyAuthStartupRegression(
		const AuthStartupRegressionRequest &request) {
	auto &domain = Core::App().domain();
	if (!domain.started() || (domain.accounts().size() != 1)) {
		FailAuthStartupRegression(
			request.name,
			"normal startup did not restore the synthetic account");
		return false;
	}
	const auto account = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	const auto startup = GetAuthStartupStateForRegressionTest();
	if (!startup.observed) {
		FailAuthStartupRegression(
			request.name,
			"normal account startup was not observed");
		return false;
	}
	if (!request.forgetPoint
		&& ((startup.userId != kAuthStartupOldUserId.bare)
			|| (startup.authorizationKeyCount <= 0))) {
		FailAuthStartupRegression(
			request.name,
			"normal startup did not load the stale user id and authorization key");
		return false;
	}
	if ((request.name == u"missing-pin"_q)
		&& (startup.hasStoredPin
			|| startup.pinUnknown
			|| !startup.configReadable
			|| startup.configHasCustomServer)) {
		FailAuthStartupRegression(
			request.name,
			"startup did not reload the distinct missing-pin fixture state");
		return false;
	}
	if ((request.name == u"incomplete-pin"_q)
		&& (!startup.hasStoredPin
			|| startup.pinUnknown
			|| !startup.configReadable
			|| startup.configHasCustomServer)) {
		FailAuthStartupRegression(
			request.name,
			"startup did not reload a readable marker with an incomplete config");
		return false;
	}
	if ((request.name == u"unreadable-config"_q)
		&& (!startup.hasStoredPin
			|| startup.pinUnknown
			|| startup.configReadable)) {
		FailAuthStartupRegression(
			request.name,
			"startup did not reload the stored marker with an unreadable config");
		return false;
	}
	if ((request.name == u"unreadable-pin"_q)
		&& (!startup.pinUnknown || !startup.configReadable)) {
		FailAuthStartupRegression(
			request.name,
			"startup did not reload unreadable prefs beside a readable config");
		return false;
	}
	const auto blockedOrPaused = account->mtp().config().blocked()
		|| account->mtp().dcOptions().unenrolled()
		|| account->local().serverForgetBlocked();
	if (!blockedOrPaused) {
		FailAuthStartupRegression(
			request.name,
			"startup resumed an account without a readable complete endpoint and pin");
		return false;
	}
	if (account->mtp().isServerEnrollmentNetworkAllowed()) {
		FailAuthStartupRegression(
			request.name,
			"startup allowed account networking before enrollment");
		return false;
	}
	if (!HasNoAuthorizationState(account)) {
		FailAuthStartupRegression(
			request.name,
			"startup retained the old identity or authorization key");
		return false;
	}
	if (request.forgetPoint) {
		const auto fingerprint = RegressionServerKey()->fingerprint();
		if (account->local().checkServerCacheBinding(
				fingerprint,
				kAuthStartupOldUserId.bare)
			!= Storage::ServerCacheBindingStatus::Match) {
			FailAuthStartupRegression(
				request.name,
				"startup did not retain the prior cache identity binding");
			return false;
		}
	}
	account->setSessionUserId(kAuthStartupNewUserId);
	if (!account->mtp().getKeysForWrite().empty()) {
		FailAuthStartupRegression(
			request.name,
			"a newly entered identity inherited authorization keys");
		return false;
	}
	if (gAuthStartupForbiddenOutboundAttempt) {
		FailAuthStartupRegression(
			request.name,
			"deferred synthetic forbidden outbound attempt was observed");
		return false;
	}
	return true;
}

} // namespace

bool AuthStartupRegressionSandboxIsValid() {
	const auto request = ParseAuthStartupRegressionRequest();
	if (!request || !Core::Launcher::Instance().customWorkingDir()) {
		std::fprintf(
			stderr,
			"Auth startup regression refused: provide a valid phase, case, and explicit -workdir.\n");
		return false;
	}
	const auto work = cWorkingDir();
	if (!AuthStartupRegressionSandboxIsValid(work)) {
		return false;
	}
	const auto selected = QFileInfo(work).canonicalFilePath();
	std::fprintf(
		stderr,
		"Auth startup regression selected workdir: %s\n",
		selected.toUtf8().constData());
	return true;
}

bool AuthStartupRegressionSandboxIsValid(
		const QString &requestedWorkingDir) {
	const auto request = ParseAuthStartupRegressionRequest();
	if (!request || requestedWorkingDir.isEmpty()) {
		std::fprintf(
			stderr,
			"Auth startup regression refused: provide a valid phase, case, and explicit -workdir.\n");
		return false;
	}
	const auto temp = QFileInfo(QDir::tempPath()).canonicalFilePath();
	const auto root = QFileInfo(qEnvironmentVariable(
		kAuthStartupRegressionRootVariable)).canonicalFilePath();
	const auto home = QFileInfo(qEnvironmentVariable("HOME")).canonicalFilePath();
	const auto work = QFileInfo(requestedWorkingDir).canonicalFilePath();
	const auto expectedWork = QFileInfo(
		root + u"/cases/"_q + request->name + u"/work"_q
	).canonicalFilePath();
	const auto markerPath = root + u"/.tdesktop-auth-startup-regression"_q;
	if (temp.isEmpty()
		|| root.isEmpty()
		|| (root == temp)
		|| !IsUnderPath(root, temp)
		|| (home != root + u"/home"_q)
		|| work.isEmpty()
		|| (work != expectedWork)
		|| !IsUnderPath(work, root)
		|| QFileInfo(markerPath).isSymLink()) {
		std::fprintf(
			stderr,
			"Auth startup regression refused: HOME, -workdir, and marker must be inside a fresh temporary root.\n");
		return false;
	}
	auto marker = QFile(markerPath);
	if (!marker.open(QIODevice::ReadOnly)
		|| marker.readAll() != kAuthStartupRegressionMarker) {
		std::fprintf(
			stderr,
			"Auth startup regression refused: disposable-root marker is missing or invalid.\n");
		return false;
	}
	return true;
}

void RunAuthStartupRegression(Fn<void(int)> done) {
	const auto request = ParseAuthStartupRegressionRequest();
	if (!request) {
		done(1);
		return;
	}
	const auto success = request->prepare
		? PrepareAuthStartupRegression(*request)
		: false;
	if (success) {
		std::fprintf(
			stderr,
			"Auth startup regression prepared: case=%s\n",
			request->name.toUtf8().constData());
	}
	if (request->prepare) {
		std::fflush(nullptr);
		std::_Exit(success ? 0 : 1);
	}
	if (qEnvironmentVariableIsSet(kAuthStartupForbiddenOutboundVariable)) {
		QTimer::singleShot(
			kAuthStartupForbiddenOutboundDelayMs,
			QCoreApplication::instance(),
			[] {
				gAuthStartupForbiddenOutboundAttempt = true;
				std::fprintf(
					stderr,
					"Auth startup regression synthetic forbidden outbound attempt: 127.0.0.1:9\n");
				gAuthStartupForbiddenSocket = std::make_unique<QTcpSocket>();
				gAuthStartupForbiddenSocket->connectToHost(
					QHostAddress::LocalHost,
					9);
			});
	}
	QTimer::singleShot(
		kAuthStartupObservationWindowMs,
		QCoreApplication::instance(),
		[request = *request, done = std::move(done)]() mutable {
			const auto passed = VerifyAuthStartupRegression(request);
			if (passed) {
				std::fprintf(
					stderr,
					"Auth startup regression passed after %dms observation: case=%s\n",
					kAuthStartupObservationWindowMs,
					request.name.toUtf8().constData());
			}
			done(passed ? 0 : 1);
		});
}

void RecordAuthStartupStateForRegressionTest(
		uint64 userId,
		int authorizationKeyCount,
		bool hasStoredPin,
		bool pinUnknown,
		bool configReadable,
		bool configHasCustomServer) {
	if (!gAuthStartupState.observed) {
		gAuthStartupState = {
			.userId = userId,
			.authorizationKeyCount = authorizationKeyCount,
			.hasStoredPin = hasStoredPin,
			.pinUnknown = pinUnknown,
			.configReadable = configReadable,
			.configHasCustomServer = configHasCustomServer,
			.observed = true,
		};
	}
}

AuthStartupStateForRegressionTest GetAuthStartupStateForRegressionTest() {
	return gAuthStartupState;
}

void RecordLifecycleWriteForRegressionTest(
		LifecycleWriteForRegressionTest operation) {
	switch (operation) {
	case LifecycleWriteForRegressionTest::AuthorizationSnapshot:
		++gLifecycleWriteCounts.authorizationSnapshot;
		break;
	case LifecycleWriteForRegressionTest::AuthorizationFailureMarker:
		++gLifecycleWriteCounts.authorizationFailureMarker;
		break;
	case LifecycleWriteForRegressionTest::CustomServerBlockMarker:
		++gLifecycleWriteCounts.customServerBlockMarker;
		break;
	}
}

void ResetLifecycleWriteCountsForRegressionTest() {
	gLifecycleWriteCounts = LifecycleWriteCountsForRegressionTest();
}

LifecycleWriteCountsForRegressionTest
GetLifecycleWriteCountsForRegressionTest() {
	return gLifecycleWriteCounts;
}
#endif

namespace {

const char kRegressionServerKey[] = R"(-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB
-----END RSA PUBLIC KEY-----)";

const char kRegressionOtherServerKey[] = R"(-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR
yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv
plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/
j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1
aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO
j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB
-----END RSA PUBLIC KEY-----)";

[[nodiscard]] std::shared_ptr<MTP::details::RSAPublicKey>
RegressionServerKey() {
	return std::make_shared<MTP::details::RSAPublicKey>(bytes::make_span(
		kRegressionServerKey,
		sizeof(kRegressionServerKey) - 1));
}

[[nodiscard]] std::shared_ptr<MTP::details::RSAPublicKey>
RegressionOtherServerKey() {
	return std::make_shared<MTP::details::RSAPublicKey>(bytes::make_span(
		kRegressionOtherServerKey,
		sizeof(kRegressionOtherServerKey) - 1));
}

[[nodiscard]] bool ConfigurePinnedServer(
		not_null<Main::Account*> account,
		std::shared_ptr<MTP::details::RSAPublicKey> key) {
	const auto configured = account->mtp().dcOptions().setCustomServer(
		MTP::CustomServer{
			.dcId = 2,
			.ip = "127.0.0.1",
			.port = 8443,
			.key = std::move(key),
		});
	return configured && account->local().writeMtpConfig(true);
}

[[nodiscard]] MTP::AuthKeyPtr RegressionAuthKey(int byte) {
	auto data = MTP::AuthKey::Data();
	std::fill(
		data.begin(),
		data.end(),
		static_cast<gsl::byte>(byte));
	return std::make_shared<MTP::AuthKey>(
		MTP::AuthKey::Type::Generated,
		2,
		data);
}

[[nodiscard]] bool HasAuthKey(
		not_null<Main::Account*> account,
		MTP::AuthKey::KeyId keyId) {
	const auto keys = account->mtp().getKeysForWrite();
	return std::any_of(keys.begin(), keys.end(), [=](const auto &key) {
		return key->keyId() == keyId;
	});
}

[[nodiscard]] bool HasNoAuthorizationState(
		not_null<Main::Account*> account) {
	return account->mtp().getKeysForWrite().empty()
		&& !account->sessionExists()
		&& (account->willHaveSessionUniqueId(nullptr) == 0);
}

[[nodiscard]] bool RestartDomain(Main::Domain &domain) {
	domain.local().writeAccounts();
	domain.finish();
	Storage::details::Sync();
	return (domain.start(QByteArray()) == Storage::StartResult::Success)
		&& !domain.accounts().empty();
}

[[nodiscard]] int FailAccountLifecycleRegression(const char *reason) {
	std::fprintf(
		stderr,
		"Account lifecycle regression failed: %s\n",
		reason);
	return 1;
}

[[nodiscard]] MTPUser RegressionUser(
	UserId id,
	bool self,
	const QString &phone);

[[nodiscard]] bool CacheMismatchWaitsForDestructiveConfirmation(
		not_null<Main::Account*> account,
		std::shared_ptr<MTP::details::RSAPublicKey> candidateKey,
		UserId candidateUserId,
		uint64 retainedFingerprint,
		uint64 retainedUserId) {
	if (!ConfigurePinnedServer(account, candidateKey)) {
		return false;
	}
	account->setSessionUserId(candidateUserId);
	if (account->createSession(
			RegressionUser(candidateUserId, true, QString()),
			std::make_unique<Main::SessionSettings>())) {
		return false;
	}
	const auto candidateFingerprint = candidateKey->fingerprint();
	if (account->sessionExists()
		|| !account->serverCacheBindingMismatchPending()
		|| account->mtp().isServerEnrollmentNetworkAllowed()
		|| account->local().checkServerCacheBinding(
			retainedFingerprint,
			retainedUserId) != Storage::ServerCacheBindingStatus::Match
		|| account->local().checkServerCacheBinding(
			candidateFingerprint,
			candidateUserId.bare)
			!= Storage::ServerCacheBindingStatus::Mismatch) {
		return false;
	}
	if (account->beginServerReenrollment(
			Main::details::ServerReenrollmentPrompt::IdentityChange,
			true)
		|| account->beginServerReenrollment(
			Main::details::ServerReenrollmentPrompt::DestructiveConfirmation,
			false)
		|| account->local().serverReenrollmentPending()) {
		return false;
	}
	return account->local().checkServerCacheBinding(
		retainedFingerprint,
		retainedUserId) == Storage::ServerCacheBindingStatus::Match;
}

template <typename Result, typename Start>
[[nodiscard]] std::optional<Result> AwaitCacheCallback(
	Start start,
	int timeoutMs = 5000) {
	struct State {
		std::optional<Result> result;
		QEventLoop *loop = nullptr;
		bool active = true;
		bool completed = false;
	};
	const auto state = std::make_shared<State>();
	auto loop = QEventLoop();
	const auto application = QCoreApplication::instance();
	if (!application) {
		return std::nullopt;
	}
	state->loop = &loop;
	QTimer::singleShot(timeoutMs, &loop, &QEventLoop::quit);
	// The callback only posts owned state; the queued handler touches the loop
	// while it is active on this thread.
	start([state, application](Result result) mutable {
		QMetaObject::invokeMethod(
			application,
			[state, result = std::move(result)]() mutable {
				if (!state->active || state->completed || !state->loop) {
					return;
				}
				state->result.emplace(std::move(result));
				state->completed = true;
				state->loop->quit();
			},
			Qt::QueuedConnection);
	});
	loop.exec();
	state->active = false;
	state->loop = nullptr;
	return std::move(state->result);
}

[[nodiscard]] bool CacheCallbackTimeoutIsSafe() {
	const auto failure = AwaitCacheCallback<int>([](auto done) {
		done(-1);
	});
	if (!failure || (*failure != -1)) {
		return false;
	}
	auto release = std::promise<void>();
	const auto waitForRelease = release.get_future().share();
	auto delayed = std::thread();
	const auto timedOut = AwaitCacheCallback<int>([&](auto done) {
		delayed = std::thread([done = std::move(done), waitForRelease]() mutable {
			waitForRelease.wait();
			done(1);
		});
	}, 1);
	release.set_value();
	delayed.join();
	QCoreApplication::processEvents();
	return !timedOut;
}

[[nodiscard]] bool CacheOperationSucceeded(
		const std::optional<Storage::Cache::Error> &result) {
	return result
		&& (result->type == Storage::Cache::Error::Type::None);
}

[[nodiscard]] bool OpenCache(
		Storage::Cache::Database &cache,
		not_null<Main::Account*> account) {
	return CacheOperationSucceeded(AwaitCacheCallback<Storage::Cache::Error>(
		[&](auto done) {
			cache.open(account->local().cacheKey(), std::move(done));
		}));
}

[[nodiscard]] bool WriteCachePayload(
		not_null<Main::Account*> account,
		const Storage::Cache::Key &key,
		const QByteArray &payload) {
	auto cache = Core::App().databases().get(
		account->local().cachePath(),
		account->local().cacheSettings());
	if (!OpenCache(*cache, account)) {
		return false;
	}
	return CacheOperationSucceeded(AwaitCacheCallback<Storage::Cache::Error>(
		[&](auto done) {
			cache->put(key, QByteArray(payload), std::move(done));
		}));
}

[[nodiscard]] bool CachePayloadMatches(
		Storage::Cache::Database &cache,
		const Storage::Cache::Key &key,
		const QByteArray &expected) {
	const auto payload = AwaitCacheCallback<QByteArray>([&](auto done) {
		cache.get(key, std::move(done));
	});
	return payload && (*payload == expected);
}

[[nodiscard]] bool PersistedCachePayloadMatches(
		not_null<Main::Account*> account,
		const Storage::Cache::Key &key,
		const QByteArray &expected) {
	auto cache = Core::App().databases().get(
		account->local().cachePath(),
		account->local().cacheSettings());
	return OpenCache(*cache, account)
		&& CachePayloadMatches(*cache, key, expected);
}

[[nodiscard]] Main::Account *FindAuthorizationBlockedAccount(
		const Main::Domain &domain) {
	for (const auto &[index, account] : domain.accounts()) {
		if (account->local().mtpAuthorizationWriteFailed()) {
			return account.get();
		}
	}
	return nullptr;
}

[[nodiscard]] MTPUser RegressionUser(
		UserId id,
		bool self,
		const QString &phone) {
	const auto flags = (self
		? MTPDuser::Flag::f_self
		: MTPDuser::Flag())
		| (phone.isEmpty()
			? MTPDuser::Flag()
			: MTPDuser::Flag::f_phone);
	return MTP_user(
		MTP_flags(flags),
		MTP_long(id.bare),
		MTPlong(),
		MTP_string(u"Regression"_q),
		MTPstring(),
		MTPstring(),
		MTP_string(phone),
		MTPUserProfilePhoto(),
		MTPUserStatus(),
		MTPint(),
		MTP_vector<MTPRestrictionReason>(0),
		MTPstring(),
		MTPstring(),
		MTPEmojiStatus(),
		MTP_vector<MTPUsername>(0),
		MTPRecentStory(),
		MTPPeerColor(),
		MTPPeerColor(),
		MTPint(),
		MTPlong(),
		MTPlong(),
		MTPlong());
}

[[nodiscard]] MTPmessages_ChatFull RegressionChatFullReply(
		ChatId chatId,
		int version,
		QString selfPhone,
		UserId creatorId) {
	const auto memberId = (creatorId == UserId(1))
		? UserId(2)
		: UserId(1);
	const auto participants = MTP_chatParticipants(
		MTP_long(chatId.bare),
		MTP_vector<MTPChatParticipant>({
			MTP_chatParticipantCreator(
				MTP_flags(MTPDchatParticipantCreator::Flags()),
				MTP_long(creatorId.bare),
				MTP_string(QString())),
			MTP_chatParticipant(
				MTP_flags(MTPDchatParticipant::Flags()),
				MTP_long(memberId.bare),
				MTP_long(creatorId.bare),
				MTP_int(0),
				MTP_string(QString())),
			MTP_chatParticipant(
				MTP_flags(MTPDchatParticipant::Flags()),
				MTP_long(UserId(9).bare),
				MTP_long(UserId(1).bare),
				MTP_int(0),
				MTP_string(QString())),
		}),
		MTP_int(version));
	const auto notifySettings = MTP_peerNotifySettings(
		MTP_flags(MTPDpeerNotifySettings::Flags()),
		MTP_boolFalse(),
		MTP_boolFalse(),
		MTP_int(0),
		MTP_notificationSoundDefault(),
		MTP_notificationSoundDefault(),
		MTP_notificationSoundDefault(),
		MTP_boolFalse(),
		MTP_boolFalse(),
		MTP_notificationSoundDefault(),
		MTP_notificationSoundDefault(),
		MTP_notificationSoundDefault());
	const auto fullChat = MTP_chatFull(
		MTP_flags(MTPDchatFull::Flags()),
		MTP_long(chatId.bare),
		MTP_string(QString()),
		participants,
		MTP_photoEmpty(MTP_long(0)),
		notifySettings,
		MTPExportedChatInvite(),
		MTP_vector<MTPBotInfo>(0),
		MTPint(),
		MTPint(),
		MTPInputGroupCall(),
		MTPint(),
		MTPPeer(),
		MTPstring(),
		MTPint(),
		MTP_vector<MTPlong>(0),
		MTP_chatReactionsNone(),
		MTPint());
	return MTP_messages_chatFull(
		fullChat,
		MTP_vector<MTPChat>(0),
		MTP_vector<MTPUser>({
			RegressionUser(UserId(1), true, selfPhone),
			RegressionUser(UserId(2), false, u"2"_q),
			RegressionUser(UserId(9), false, u"9"_q),
		}));
}

[[nodiscard]] bool HasParticipant(
		not_null<ChatData*> chat,
		UserId id) {
	return std::any_of(
		chat->participants.begin(),
		chat->participants.end(),
		[id](not_null<UserData*> user) {
			return peerToUser(user->id) == id;
		});
}

[[nodiscard]] bool HasExpectedParticipants(
		not_null<ChatData*> chat,
		UserId creatorId) {
	return (chat->participants.size() == 3)
		&& (chat->creator == creatorId)
		&& HasParticipant(chat, UserId(1))
		&& HasParticipant(chat, UserId(2))
		&& HasParticipant(chat, UserId(9));
}

[[nodiscard]] int FailChatParticipantsRegression(const char *reason) {
	std::fprintf(
		stderr,
		"Chat participants regression failed: %s\n",
		reason);
	return 1;
}

[[nodiscard]] int StartChatParticipantsRegression(
		Main::Domain &domain,
		Fn<void(int)> done) {
	if (domain.accounts().size() > Main::Domain::kPremiumMaxAccounts - 2) {
		return FailChatParticipantsRegression(
			"not enough account slots for isolated stock and pinned sessions");
	}
	const auto selfId = UserId(1);
	const auto chatId = ChatId(1051);
	const auto stock = domain.add(MTP::Environment::Production);
	stock->mtp().stopForServerEnrollment();
	stock->setSessionUserId(selfId);
	if (!stock->createSession(
			RegressionUser(selfId, true, QString()),
			std::make_unique<Main::SessionSettings>())) {
		return FailChatParticipantsRegression(
			"could not create the stock test session");
	}
	const auto stockChat = stock->session().data().chat(chatId);
	const auto stockPeer = not_null<PeerData*>(
		static_cast<PeerData*>(&*stockChat));
	stock->session().api().processFullPeer(
		stockPeer,
		RegressionChatFullReply(chatId, 1, QString(), UserId(2)));
	if (stock->session().user()->isLoaded()
		|| !stockChat->participants.empty()) {
		return FailChatParticipantsRegression(
			"stock session accepted phone-free self in full chat info");
	}
	stock->session().api().processFullPeer(
		stockPeer,
		RegressionChatFullReply(chatId, 2, u"+10000000001"_q, UserId(2)));
	if (!stock->session().user()->isLoaded()
		|| !HasExpectedParticipants(stockChat, UserId(2))) {
		return FailChatParticipantsRegression(
			"stock session with phone did not load creator and members");
	}

	const auto pinned = domain.add(MTP::Environment::Production);
	pinned->mtp().stopForServerEnrollment();
	if (!ConfigurePinnedServer(pinned, RegressionServerKey())) {
		return FailChatParticipantsRegression(
			"could not pin the custom test server");
	}
	pinned->setSessionUserId(selfId);
	if (!pinned->createSession(
			RegressionUser(selfId, true, QString()),
			std::make_unique<Main::SessionSettings>())) {
		return FailChatParticipantsRegression(
			"could not create the pinned test session");
	}
	const auto pinnedChat = pinned->session().data().chat(chatId);
	const auto pinnedPeer = not_null<PeerData*>(
		static_cast<PeerData*>(&*pinnedChat));
	pinned->session().api().processFullPeer(
		pinnedPeer,
		RegressionChatFullReply(chatId, 1, QString(), UserId(2)));
	if (!pinned->session().user()->isLoaded()
		|| !HasExpectedParticipants(pinnedChat, UserId(2))) {
		return FailChatParticipantsRegression(
			"pinned phone-free self did not retain creator and members");
	}

	const auto actionChatId = ChatId(1052);
	const auto stockActionChat = stock->session().data().chat(actionChatId);
	const auto stockActionPeer = not_null<PeerData*>(
		static_cast<PeerData*>(&*stockActionChat));
	stock->session().api().processFullPeer(
		stockActionPeer,
		RegressionChatFullReply(
			actionChatId,
			1,
			u"+10000000001"_q,
			selfId));
	stockActionChat->setFlags(ChatDataFlag::Creator);
	if (!HasExpectedParticipants(stockActionChat, selfId)
		|| !stockActionChat->canEditInformation()
		|| !stockActionChat->canAddMembers()
		|| !stockActionChat->canAddAdmins()
		|| !stockActionChat->canBanMembers()) {
		return FailChatParticipantsRegression(
			"stock creator lost a supported basic-group action");
	}

	const auto pinnedActionChat = pinned->session().data().chat(actionChatId);
	const auto pinnedActionPeer = not_null<PeerData*>(
		static_cast<PeerData*>(&*pinnedActionChat));
	pinned->session().api().processFullPeer(
		pinnedActionPeer,
		RegressionChatFullReply(actionChatId, 1, QString(), selfId));
	pinnedActionChat->setFlags(ChatDataFlag::Creator);
	if (!HasExpectedParticipants(pinnedActionChat, selfId)
		|| !pinnedActionChat->canEditInformation()
		|| !pinnedActionChat->canAddMembers()
		|| pinnedActionChat->canAddAdmins()
		|| !pinnedActionChat->canBanMembers()) {
		return FailChatParticipantsRegression(
			"pinned creator lost a supported action or retained admin grants");
	}
	if (!pinnedActionChat->usesCustomServer()
		|| pinnedActionChat->isDeactivated()
		|| pinnedActionChat->migrateTo()) {
		return FailChatParticipantsRegression(
			"pinned migration fixture is not an active custom-server group");
	}
	pinned->mtp().stopForServerEnrollment();

	struct MigrationResult {
		int done = 0;
		int failed = 0;
		QString error;
	};
	const auto migration = std::make_shared<MigrationResult>();
	pinned->session().api().migrateChat(
		pinnedActionChat,
		[migration](not_null<ChannelData*>) {
			++migration->done;
		},
		[migration](const QString &error) {
			++migration->failed;
			migration->error = error;
		});
	crl::on_main([=] {
		std::fprintf(
			stderr,
			"Pinned migration regression: done=%d failed=%d error=%s\n",
			migration->done,
			migration->failed,
			migration->error.toUtf8().constData());
		if (migration->done != 0
			|| migration->failed != 1
			|| migration->error != u"CLIENT_BAD_MIGRATION"_q) {
			done(FailChatParticipantsRegression(
				"pinned basic-group migration was not rejected locally"));
			return;
		}
		std::fprintf(stderr, "Chat participants regression passed.\n");
		done(0);
	});
	return 0;
}

[[nodiscard]] int StartAccountLifecycleRegression(Fn<void(int)> done) {
	const auto failureVariable = QByteArray(
		"TDESKTOP_FAIL_MTP_AUTHORIZATION_WRITE");
	const auto failWrites = gsl::finally([&] {
		qunsetenv(failureVariable.constData());
	});

	auto &domain = Core::App().domain();
	if (!domain.started()) {
		return FailAccountLifecycleRegression(
			"application domain did not start");
	}
	if (Core::App().activePrimaryWindow()) {
		return FailAccountLifecycleRegression(
			"application unexpectedly created a primary window");
	}
	if (domain.accounts().size() != 1
		|| domain.accounts().front().account->sessionExists()) {
		return FailAccountLifecycleRegression(
			"regression requires one fresh account in its isolated workdir");
	}

	// This is the production post-auth caller. It must keep the session
	// unpublished when the synchronous authorization write is refused.
	const auto account = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	const auto cacheKey = Storage::Cache::Key{
		0x4d41494e31303632ULL,
		0x4341434845504159ULL,
	};
	const auto cachePayload = QByteArray(
		"main-1062-cache-regression-payload");
	if (!CacheCallbackTimeoutIsSafe()) {
		return FailAccountLifecycleRegression(
			"cache callback wait mishandled failure or late completion");
	}
	if (!WriteCachePayload(account, cacheKey, cachePayload)) {
		return FailAccountLifecycleRegression(
			"could not seed the cache payload");
	}
	if (!account->sessionExists()
		&& !account->mtp().dcOptions().hasCustomServer()
		&& (!account->mtp().dcOptions().unenrolled()
			|| !account->mtp().dcOptions().configEnumDcIds().empty())) {
		// A fresh account is allowed to show enrollment, but it must not
		// carry the built-in production table while it waits there.
		return FailAccountLifecycleRegression(
			"fresh account retained production endpoints before enrollment");
	}
	// Sender destruction must cancel a refused request before queued delivery.
	account->mtp().stopForServerEnrollment();
	auto cancelledFailures = 0;
	{
		auto sender = MTP::Sender(&account->mtp());
		const auto requestId = sender.request(MTPupdates_GetState(
		)).fail([&](const MTP::Error &) {
			++cancelledFailures;
		}).send();
		if (!sender.pending(requestId)) {
			return FailAccountLifecycleRegression(
				"stopped sender did not retain its request");
		}
	}
	QCoreApplication::processEvents();
	if (cancelledFailures) {
		return FailAccountLifecycleRegression(
			"destroyed sender delivered a cancelled request");
	}
	auto liveFailures = 0;
	{
		auto sender = MTP::Sender(&account->mtp());
		const auto requestId = sender.request(MTPupdates_GetState(
		)).fail([&](const MTP::Error &error) {
			if (MTP::IsServerEnrollmentPausedError(error)) {
				++liveFailures;
			}
		}).send();
		if (!sender.pending(requestId)) {
			return FailAccountLifecycleRegression(
				"paused sender did not retain its request");
		}
		QCoreApplication::processEvents();
		if (sender.pending(requestId) || liveFailures != 1) {
			return FailAccountLifecycleRegression(
				"paused request was not rejected locally");
		}
	}
	const auto originalKey = RegressionServerKey();
	const auto originalFingerprint = originalKey->fingerprint();
	if (!ConfigurePinnedServer(account, originalKey)) {
		return FailAccountLifecycleRegression(
			"could not pin the test server");
	}
	account->setSessionUserId(UserId(4242));
	qputenv(failureVariable.constData(), "1");
	const auto published = account->createSession(
		UserId(4242),
		QByteArray(),
		0,
		std::make_unique<Main::SessionSettings>());
	if (published || account->sessionExists()
		|| account->willHaveSessionUniqueId(nullptr) == 0
		|| !account->local().mtpAuthorizationWriteFailed()) {
		return FailAccountLifecycleRegression(
			"post-auth write failure published a session or lost its marker");
	}
	qunsetenv(failureVariable.constData());

	// The failed post-auth write already persisted the block marker; leaving
	// it in place verifies startup restores that durable block.
	if (!RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"could not restart after the post-auth write failure");
	}

	const auto blocked = FindAuthorizationBlockedAccount(domain);
	if (!blocked || !blocked->mtp().config().blocked()) {
		return FailAccountLifecycleRegression(
			"post-auth failure did not restore a blocked account");
	}
	if (!RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"could not restart after blocked account teardown");
	}
	const auto stillBlocked = FindAuthorizationBlockedAccount(domain);
	if (!stillBlocked || !stillBlocked->mtp().config().blocked()) {
		return FailAccountLifecycleRegression(
			"blocked teardown cleared the durable authorization failure");
	}
	const auto restarted = Main::details::CommitServerForget(
		&stillBlocked->local(),
		Storage::ServerCacheBinding{
			.fingerprintKnown = true,
			.fingerprint = originalFingerprint,
			.userIdKnown = true,
			.userId = 4242,
		},
		[] {});
	if (!restarted
		|| stillBlocked->local().hasStoredCustomServer()
		|| stillBlocked->local().mtpAuthorizationWriteFailed()) {
		return FailAccountLifecycleRegression(
			"Forget did not durably clear the blocked server state");
	}
	if (stillBlocked->local().mtpAuthorizationDataExistsForRegressionTest()) {
		return FailAccountLifecycleRegression(
			"Forget left the persisted authorization snapshot before restart");
	}

	if (!RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"could not restart after Forget");
	}
	const auto forgotten = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (!PersistedCachePayloadMatches(
			forgotten,
			cacheKey,
			cachePayload)
		|| !forgotten->mtp().dcOptions().unenrolled()
		|| forgotten->mtp().dcOptions().blocked()
		|| forgotten->local().hasStoredCustomServer()
		|| forgotten->local().mtpAuthorizationWriteFailed()
		|| !HasNoAuthorizationState(forgotten)
		|| !forgotten->mtp().dcOptions().configEnumDcIds().empty()) {
		return FailAccountLifecycleRegression(
			"Forget did not restart unenrolled without auth data or endpoints");
	}
	auto pausedFailures = 0;
	{
		auto sender = MTP::Sender(&forgotten->mtp());
		const auto requestId = sender.request(MTPupdates_GetState(
		)).fail([&](const MTP::Error &error) {
			if (MTP::IsServerEnrollmentPausedError(error)) {
				++pausedFailures;
			}
		}).send();
		if (!sender.pending(requestId)) {
			return FailAccountLifecycleRegression(
				"unenrolled sender did not retain its request");
		}
		QCoreApplication::processEvents();
		if (sender.pending(requestId) || pausedFailures != 1) {
			return FailAccountLifecycleRegression(
				"unenrolled request was not rejected locally");
		}
	}

	const auto initialKey = RegressionAuthKey(0x11);
	forgotten->mtp().dcPersistentKeyChanged(2, initialKey);
	if (!ConfigurePinnedServer(forgotten, originalKey)) {
		return FailAccountLifecycleRegression(
			"could not configure the matching server after Forget");
	}
	forgotten->setSessionUserId(UserId(4242));
	if (!forgotten->createSession(
			RegressionUser(UserId(4242), true, QString()),
			std::make_unique<Main::SessionSettings>())
		|| !forgotten->sessionExists()
		|| forgotten->serverCacheBindingMismatchPending()
		|| forgotten->local().checkServerCacheBinding(
			originalFingerprint,
			4242) != Storage::ServerCacheBindingStatus::Match
		|| !CachePayloadMatches(
			forgotten->session().data().cache(),
			cacheKey,
			cachePayload)) {
		return FailAccountLifecycleRegression(
			"matching server and user identity did not reuse the retained cache payload");
	}
	forgotten->mtp().resume();
	const auto finalKey = RegressionAuthKey(0x22);
	const auto finalKeyId = finalKey->keyId();
	forgotten->mtp().dcPersistentKeyChanged(2, finalKey);
	if (!RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"could not restart after active account teardown");
	}
	auto active = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (!active->sessionExists()
		|| !HasAuthKey(active, finalKeyId)
		|| !active->local().mtpAuthorizationDataExistsForRegressionTest()) {
		return FailAccountLifecycleRegression(
			"active teardown did not persist its final authorization snapshot");
	}

	const auto teardownFailureKey = RegressionAuthKey(0x33);
	active->mtp().dcPersistentKeyChanged(2, teardownFailureKey);
	qputenv(failureVariable.constData(), "1");
	if (!RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"could not restart after teardown-only authorization failure");
	}
	qunsetenv(failureVariable.constData());
	auto failedTeardown = FindAuthorizationBlockedAccount(domain);
	if (!failedTeardown
		|| !failedTeardown->mtp().config().blocked()
		|| !failedTeardown->local().mtpAuthorizationWriteFailed()) {
		return FailAccountLifecycleRegression(
			"active teardown-only failure did not block the next startup");
	}
	ResetLifecycleWriteCountsForRegressionTest();
	if (!failedTeardown->local().writeMtpAuthorizationFailure()) {
		return FailAccountLifecycleRegression(
			"could not rewrite the retained authorization failure marker");
	}
	const auto markerRewriteAttempts = GetLifecycleWriteCountsForRegressionTest();
	if (markerRewriteAttempts.authorizationSnapshot != 0
		|| markerRewriteAttempts.authorizationFailureMarker != 1
		|| markerRewriteAttempts.customServerBlockMarker != 0) {
		return FailAccountLifecycleRegression(
			"authorization failure marker observer missed an identical-value rewrite");
	}
	domain.local().writeAccounts();
	ResetLifecycleWriteCountsForRegressionTest();
	domain.finish();
	const auto blockedTeardownAttempts = GetLifecycleWriteCountsForRegressionTest();
	if (blockedTeardownAttempts.authorizationSnapshot != 0
		|| blockedTeardownAttempts.authorizationFailureMarker != 0
		|| blockedTeardownAttempts.customServerBlockMarker != 0) {
		return FailAccountLifecycleRegression(
			"blocked account teardown attempted an authorization or marker write");
	}
	Storage::details::Sync();
	if ((domain.start(QByteArray()) != Storage::StartResult::Success)
		|| domain.accounts().empty()) {
		return FailAccountLifecycleRegression(
			"could not restart after blocked teardown");
	}
	failedTeardown = FindAuthorizationBlockedAccount(domain);
	if (!failedTeardown
		|| !failedTeardown->mtp().config().blocked()
		|| !failedTeardown->local().mtpAuthorizationWriteFailed()) {
		return FailAccountLifecycleRegression(
			"blocked teardown changed its durable authorization state");
	}
	if (!failedTeardown->local().mtpAuthorizationDataExistsForRegressionTest()) {
		return FailAccountLifecycleRegression(
			"blocked teardown lost the prior authorization snapshot");
	}
	if (!Main::details::CommitServerForget(
			&failedTeardown->local(),
			Storage::ServerCacheBinding{
				.fingerprintKnown = true,
				.fingerprint = originalFingerprint,
				.userIdKnown = true,
				.userId = 4242,
			},
			[] {})) {
		return FailAccountLifecycleRegression(
			"could not Forget the blocked account after teardown");
	}
	if (failedTeardown->local().mtpAuthorizationDataExistsForRegressionTest()) {
		return FailAccountLifecycleRegression(
			"Forget left the prior authorization snapshot before restart");
	}
	if (!RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"could not return to enrollment after teardown block");
	}
	auto unenrolled = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (!unenrolled->mtp().dcOptions().unenrolled()
		|| unenrolled->local().mtpAuthorizationWriteFailed()
		|| !HasNoAuthorizationState(unenrolled)
		|| unenrolled->local().checkServerCacheBinding(
			originalFingerprint,
			4242) != Storage::ServerCacheBindingStatus::Match) {
		return FailAccountLifecycleRegression(
			"Forget did not retain only the cache identity binding");
	}
	if (!RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"paused teardown did not complete its restart");
	}
	unenrolled = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (!unenrolled->mtp().dcOptions().unenrolled()
		|| unenrolled->local().mtpAuthorizationWriteFailed()
		|| !HasNoAuthorizationState(unenrolled)) {
		return FailAccountLifecycleRegression(
			"paused teardown wrote authorization data or a failure marker");
	}

	if (!CacheMismatchWaitsForDestructiveConfirmation(
			unenrolled,
			RegressionOtherServerKey(),
			UserId(4242),
			originalFingerprint,
			4242)) {
		return FailAccountLifecycleRegression(
			"changed server fingerprint bypassed cache confirmation");
	}
	if (!PersistedCachePayloadMatches(
			unenrolled,
			cacheKey,
			cachePayload)) {
		return FailAccountLifecycleRegression(
			"declined fingerprint change damaged the cached payload");
	}
	if (!Main::details::CommitServerForget(
			&unenrolled->local(),
			Storage::ServerCacheBinding{
				.fingerprintKnown = true,
				.fingerprint = originalFingerprint,
				.userIdKnown = true,
				.userId = 4242,
			},
			[] {})
		|| !RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"could not reset the declined fingerprint change");
	}
	unenrolled = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (!CacheMismatchWaitsForDestructiveConfirmation(
			unenrolled,
			originalKey,
			UserId(5252),
			originalFingerprint,
			4242)) {
		return FailAccountLifecycleRegression(
			"changed user id bypassed cache confirmation");
	}
	if (!PersistedCachePayloadMatches(
			unenrolled,
			cacheKey,
			cachePayload)) {
		return FailAccountLifecycleRegression(
			"declined user-id change damaged the cached payload");
	}
	if (!unenrolled->beginServerReenrollment(
			Main::details::ServerReenrollmentPrompt::DestructiveConfirmation,
			true)
		|| !unenrolled->local().serverReenrollmentPending()
		|| !RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"confirmed identity change did not schedule destructive cleanup");
	}
	unenrolled = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (!unenrolled->mtp().dcOptions().unenrolled()
		|| unenrolled->local().mtpAuthorizationWriteFailed()
		|| !HasNoAuthorizationState(unenrolled)
		|| unenrolled->local().hasStoredCustomServer()
		|| unenrolled->local().customServerPinUnknown()
		|| unenrolled->local().checkServerCacheBinding(
			originalFingerprint,
			4242) != Storage::ServerCacheBindingStatus::None) {
		return FailAccountLifecycleRegression(
			"confirmed identity change did not discard the old cache binding");
	}

	unenrolled->local().writeCustomServerBlocked(false);
	if (!RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"could not restart the synthetic blocked account");
	}
	auto blockedWithoutAuthorizationFailure = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (!blockedWithoutAuthorizationFailure->mtp().config().blocked()
		|| blockedWithoutAuthorizationFailure->local().mtpAuthorizationWriteFailed()
		|| !HasNoAuthorizationState(blockedWithoutAuthorizationFailure)
		|| !blockedWithoutAuthorizationFailure->local().hasStoredCustomServer()
		|| blockedWithoutAuthorizationFailure->local().customServerPinUnknown()) {
		return FailAccountLifecycleRegression(
			"blocked startup did not retain its existing marker and empty auth state");
	}
	ResetLifecycleWriteCountsForRegressionTest();
	qputenv(failureVariable.constData(), "1");
	const auto authorizationAttemptFailed =
		!blockedWithoutAuthorizationFailure->local().writeMtpAuthorization();
	qunsetenv(failureVariable.constData());
	const auto authorizationAttempts = GetLifecycleWriteCountsForRegressionTest();
	if (!authorizationAttemptFailed
		|| authorizationAttempts.authorizationSnapshot != 1
		|| authorizationAttempts.authorizationFailureMarker != 0
		|| authorizationAttempts.customServerBlockMarker != 0
		|| blockedWithoutAuthorizationFailure->local().mtpAuthorizationWriteFailed()
		|| !HasNoAuthorizationState(blockedWithoutAuthorizationFailure)) {
		return FailAccountLifecycleRegression(
			"authorization snapshot observer missed an isolated write attempt");
	}
	ResetLifecycleWriteCountsForRegressionTest();
	blockedWithoutAuthorizationFailure->local().writeCustomServerBlocked(false);
	const auto markerAttempts = GetLifecycleWriteCountsForRegressionTest();
	if (markerAttempts.authorizationSnapshot != 0
		|| markerAttempts.authorizationFailureMarker != 0
		|| markerAttempts.customServerBlockMarker != 1
		|| !blockedWithoutAuthorizationFailure->local().hasStoredCustomServer()) {
		return FailAccountLifecycleRegression(
			"block marker observer missed an identical-value rewrite");
	}
	domain.local().writeAccounts();
	ResetLifecycleWriteCountsForRegressionTest();
	domain.finish();
	const auto teardownAttempts = GetLifecycleWriteCountsForRegressionTest();
	if (teardownAttempts.authorizationSnapshot != 0
		|| teardownAttempts.authorizationFailureMarker != 0
		|| teardownAttempts.customServerBlockMarker != 0) {
		return FailAccountLifecycleRegression(
			"blocked account teardown attempted an authorization or marker write");
	}
	Storage::details::Sync();
	if ((domain.start(QByteArray()) != Storage::StartResult::Success)
		|| domain.accounts().empty()) {
		return FailAccountLifecycleRegression(
			"blocked teardown did not complete its restart");
	}
	blockedWithoutAuthorizationFailure = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (!blockedWithoutAuthorizationFailure->mtp().config().blocked()
		|| blockedWithoutAuthorizationFailure->local().mtpAuthorizationWriteFailed()
		|| !HasNoAuthorizationState(blockedWithoutAuthorizationFailure)) {
		return FailAccountLifecycleRegression(
			"blocked teardown wrote authorization data or a failure marker");
	}

	return StartChatParticipantsRegression(domain, std::move(done));
}

} // namespace

void RunAccountLifecycleRegression(Fn<void(int)> done) {
	if (const auto result = StartAccountLifecycleRegression(done)) {
		done(result);
	}
}

} // namespace Tests
