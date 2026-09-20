/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "main/main_account_persistence.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/mtproto_auth_key.h"
#include "mtproto/mtproto_config.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/mtproto_server_enrollment.h"
#include "mtproto/session.h"
#include "storage/details/storage_file_utilities.h"
#include "storage/storage_account.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QMetaObject>
#include <QtCore/QSemaphore>
#include <QtCore/QTemporaryDir>
#include <QtCore/QThread>
#include <QtCore/Qt>
#include <QtGui/QKeyEvent>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

namespace {

using namespace MTP;

const char kEnrollmentServerKey[] = "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n\
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n\
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n\
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n\
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n\
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n\
-----END RSA PUBLIC KEY-----";

[[nodiscard]] std::shared_ptr<details::RSAPublicKey>
MakeEnrollmentServerKey() {
	return std::make_shared<details::RSAPublicKey>(bytes::make_span(
		kEnrollmentServerKey,
		sizeof(kEnrollmentServerKey) - 1));
}

[[nodiscard]] std::shared_ptr<MTP::Config> MakeEnrollmentConfig() {
	auto result = std::make_shared<MTP::Config>(MTP::Environment::Production);
	Expects(result->dcOptions().setCustomServer(CustomServer{
		.dcId = 2,
		.ip = "10.4.1.7",
		.port = 8443,
		.key = MakeEnrollmentServerKey(),
	}));
	return result;
}

[[nodiscard]] MTP::AuthKeyPtr MakeEnrollmentStorageKey() {
	return std::make_shared<MTP::AuthKey>(
		MTP::AuthKey::Data{ { gsl::byte{} } });
}

[[nodiscard]] std::unique_ptr<Storage::Account> MakeEnrollmentStorageAccount(
		const QString &basePath,
		const MTP::AuthKeyPtr &key,
		Fn<QByteArray()> serializeMtpAuthorization = nullptr,
		Fn<void(const QByteArray &)> restoreMtpAuthorization = nullptr,
		Fn<bool()> writeMtpAuthorizationOverride = nullptr) {
	return std::make_unique<Storage::Account>(
		basePath,
		key,
		MakeEnrollmentConfig(),
		false,
		std::move(serializeMtpAuthorization),
		std::move(restoreMtpAuthorization),
		std::move(writeMtpAuthorizationOverride));
}

[[nodiscard]] bool HasReadableEnrollmentMap(
		const QString &basePath,
		const MTP::AuthKeyPtr &key) {
	Storage::details::FileReadDescriptor file;
	if (!Storage::details::ReadFile(file, u"map"_q, basePath)) {
		return false;
	}

	QByteArray legacySalt, legacyKey, encrypted;
	file.stream >> legacySalt >> legacyKey >> encrypted;
	if (!Storage::details::CheckStreamStatus(file.stream)) {
		return false;
	}

	Storage::details::EncryptedDescriptor map;
	if (!Storage::details::DecryptLocal(map, encrypted, key)) {
		return false;
	}

	quint32 keyType = 0;
	quint64 prefsKey = 0;
	map.stream >> keyType >> prefsKey;
	return Storage::details::CheckStreamStatus(map.stream)
		&& keyType == 0x1e
		&& prefsKey != 0;
}

[[nodiscard]] std::unique_ptr<MTP::Config> ReadEnrollmentConfig(
		const QString &basePath,
		const MTP::AuthKeyPtr &key) {
	Storage::details::FileReadDescriptor file;
	if (!Storage::details::ReadEncryptedFile(
			file,
			u"config"_q,
			basePath,
			key)) {
		return nullptr;
	}

	QByteArray serialized;
	file.stream >> serialized;
	if (!Storage::details::CheckStreamStatus(file.stream)) {
		return nullptr;
	}
	return MTP::Config::FromSerialized(serialized);
}

[[nodiscard]] bool HasReadableEnrollmentConfig(
		const QString &basePath,
		const MTP::AuthKeyPtr &key) {
	const auto restored = ReadEnrollmentConfig(basePath, key);
	return restored != nullptr && restored->hasCustomServer();
}

TEST_CASE(ReplaceInvalidatesQueuedStopFromPreviousEnrollment) {
	ServerEnrollmentGate gate;
	CHECK(gate.start());
	CHECK(gate.pause());
	CHECK(!gate.networkAllowed());

	const auto staleStop = gate.stopToken();
	const auto resumed = gate.resume();
	CHECK(resumed.resumed);
	CHECK(resumed.wasStarted);
	CHECK(gate.networkAllowed());
	CHECK(!gate.stopTokenIsCurrent(staleStop));

	auto stopApplied = false;
	if (gate.stopTokenIsCurrent(staleStop)) {
		stopApplied = true;
	}
	CHECK(!stopApplied);
}

TEST_CASE(UnconfirmedEnrollmentDoesNotAllowNetwork) {
	ServerEnrollmentGate gate(true);
	CHECK(!gate.networkAllowed());
	CHECK(!gate.start());
	CHECK(!gate.pause());

	const auto resumed = gate.resume();
	CHECK(resumed.resumed);
	CHECK(!resumed.wasStarted);
	// Clearing the pause does not create a session. The owning instance
	// starts it only after the confirmed pin has been persisted.
	CHECK(!gate.networkAllowed());
}

TEST_CASE(ConfirmedEnrollmentStartsNetworkAfterPinPersistence) {
	ServerEnrollmentGate gate(true);
	auto persisted = false;
	const auto committed = CommitServerEnrollment(
		[] { return true; },
		[&] {
			persisted = true;
			return true;
		},
		[&] {
			const auto resumed = gate.resume();
			CHECK(resumed.resumed);
			CHECK(!resumed.wasStarted);
			CHECK(persisted);
			CHECK(gate.start());
		});

	CHECK(committed);
	CHECK(persisted);
	CHECK(gate.networkAllowed());
}

TEST_CASE(CurrentStopRemainsEffectiveUntilTheNextReplacement) {
	ServerEnrollmentGate gate;
	CHECK(gate.start());
	CHECK(gate.pause());
	CHECK(!gate.networkAllowed());

	const auto currentStop = gate.stopToken();
	CHECK(gate.stopTokenIsCurrent(currentStop));

	const auto resumed = gate.resume();
	CHECK(resumed.resumed);
	CHECK(!gate.stopTokenIsCurrent(currentStop));

	CHECK(gate.pause());
	CHECK(!gate.networkAllowed());
	const auto replacementStop = gate.stopToken();
	CHECK(gate.stopTokenIsCurrent(replacementStop));
	CHECK(!gate.stopTokenIsCurrent(currentStop));

	auto stopApplied = false;
	if (gate.stopTokenIsCurrent(currentStop)) {
		stopApplied = true;
	}
	CHECK(!stopApplied);
	if (gate.stopTokenIsCurrent(replacementStop)) {
		stopApplied = true;
	}
	CHECK(stopApplied);
}

// A selected endpoint failure can leave a response or timer callback queued
// after the enrollment attempt is cancelled. That callback must not reopen
// the gate or introduce a fallback endpoint in the next attempt.
TEST_CASE(LateSelectedEndpointCallbackCannotReopenTheGate) {
	ServerEnrollmentGate gate;
	CHECK(gate.start());
	const auto failedAttempt = gate.stopToken();
	CHECK(gate.pause());

	auto callbackReopenedGate = false;
	if (gate.stopTokenIsCurrent(failedAttempt)) {
		callbackReopenedGate = true;
		static_cast<void>(gate.resume());
	}

	CHECK(!callbackReopenedGate);
	CHECK(!gate.networkAllowed());
}

TEST_CASE(RejectedEnrollmentDoesNotReachNetworkOrAuth) {
	auto networkCalls = 0;
	auto authCalls = 0;
	const auto committed = CommitServerEnrollment(
		[] { return false; },
		[&] {
			++networkCalls;
			return true;
		},
		[&] { ++authCalls; });

	CHECK(!committed);
	CHECK_EQ(networkCalls, 0);
	CHECK_EQ(authCalls, 0);
}

TEST_CASE(PinPersistencePrecedesTheFirstConnection) {
	auto events = std::vector<int>();
	const auto committed = CommitServerEnrollment(
		[&] {
			events.push_back(1); // set the verified endpoint and key
			return true;
		},
		[&] {
			events.push_back(2); // persist the pin
			return true;
		},
		[&] { events.push_back(3); }); // start network and auth

	CHECK(committed);
	CHECK_EQ(int(events.size()), 3);
	CHECK_EQ(events[0], 1);
	CHECK_EQ(events[1], 2);
	CHECK_EQ(events[2], 3);
}

TEST_CASE(EnrollmentPersistenceFailureRollsBackBeforeReturning) {
	auto rolledBack = false;
	auto resumed = false;
	const auto committed = CommitServerEnrollment(
		[] { return true; },
		[] { return false; },
		[&] { resumed = true; },
		[&] { rolledBack = true; });

	CHECK(!committed);
	CHECK(!resumed);
	CHECK(rolledBack);
}

TEST_CASE(EnrollmentPersistsReadableMapBeforeConfig) {
	QTemporaryDir directory;
	CHECK(directory.isValid());
	const auto basePath = directory.path() + QDir::separator();
	const auto key = MakeEnrollmentStorageKey();
	auto account = MakeEnrollmentStorageAccount(basePath, key);

	const auto committed = CommitServerEnrollment(
		[] { return true; },
		[&] { return account->writeMtpConfig(true); },
		[] {});

	CHECK(committed);
	CHECK(HasReadableEnrollmentMap(basePath, key));
	CHECK(HasReadableEnrollmentConfig(basePath, key));
}

TEST_CASE(EnrollmentRestartRestoresBoundServerStep) {
	QTemporaryDir directory;
	CHECK(directory.isValid());
	const auto basePath = directory.path() + QDir::separator();
	const auto key = MakeEnrollmentStorageKey();
	auto account = MakeEnrollmentStorageAccount(basePath, key);
	auto resumed = false;

	const auto committed = CommitServerEnrollment(
		[] { return true; },
		[&] { return account->writeMtpConfig(true); },
		[&] { resumed = true; });

	CHECK(committed);
	CHECK(resumed);
	account.reset();

	const auto restored = ReadEnrollmentConfig(basePath, key);
	CHECK(restored != nullptr);
	if (!restored) {
		return;
	}
	CHECK(restored->hasCustomServer());
	const auto server = restored->customServer();
	CHECK_EQ(server.ip, "10.4.1.7");
	CHECK_EQ(server.port, 8443);
	CHECK(server.key != nullptr);
	CHECK(MTP::ShouldOpenServerEnrollment(
		restored->hasCustomServer(),
		false));
	CHECK(!MTP::ShouldOpenServerEnrollment(false, false));
	CHECK(MTP::ShouldOpenServerEnrollment(false, true));
}

TEST_CASE(ServerReenrollmentConfirmationLeavesBlockedPinUnchanged) {
	QTemporaryDir directory;
	CHECK(directory.isValid());

	const auto previousWorkingDir = QDir::currentPath();
	QDir::setCurrent(directory.path());
	const auto restoreWorkingDir = gsl::finally([&] {
		QDir::setCurrent(previousWorkingDir);
	});

	const auto basePath = directory.path() + u"account/"_q;
	const auto key = MakeEnrollmentStorageKey();
	auto config = MakeEnrollmentConfig();
	CHECK(config->dcOptions().markAuthorized(2));
	auto account = std::make_unique<Storage::Account>(
		basePath,
		key,
		std::move(config),
		false,
		[] { return QByteArray("old-server-auth-key"); });
	CHECK(account->writeMtpConfig(true));
	CHECK(account->writeMtpData(true));

	MTP::ServerEnrollmentGate gate;
	CHECK(gate.start());
	CHECK(gate.pause());
	auto wipeCalls = 0;
	const auto wipe = [&] {
		++wipeCalls;
		const auto written = account->writeServerReenrollmentTombstone();
		if (written) {
			static_cast<void>(gate.resume());
		}
		return written;
	};

	// Canceling the identity warning and declining the final prompt must not
	// reach the destructive callback, even though the first prompt was seen.
	CHECK(!Main::details::CommitServerReenrollment(
		Main::details::ServerReenrollmentPrompt::IdentityChange,
		false,
		wipe));
	CHECK(!Main::details::CommitServerReenrollment(
		Main::details::ServerReenrollmentPrompt::IdentityChange,
		true,
		wipe));
	CHECK(!Main::details::CommitServerReenrollment(
		Main::details::ServerReenrollmentPrompt::DestructiveConfirmation,
		false,
		wipe));

	CHECK_EQ(wipeCalls, 0);
	CHECK(!account->serverReenrollmentPending());
	CHECK(!gate.networkAllowed());
	const auto restored = ReadEnrollmentConfig(basePath, key);
	CHECK(restored != nullptr);
	if (restored) {
		CHECK(restored->hasCustomServer());
		CHECK(restored->dcOptions().isAuthorized(2));
	}
}

TEST_CASE(ServerReenrollmentWipeRemovesFutureStores) {
	QTemporaryDir directory;
	CHECK(directory.isValid());

	const auto previousWorkingDir = QDir::currentPath();
	QDir::setCurrent(directory.path());
	const auto restoreWorkingDir = gsl::finally([&] {
		QDir::setCurrent(previousWorkingDir);
	});

	const auto basePath = directory.path() + u"account/"_q;
	const auto key = MakeEnrollmentStorageKey();
	const auto serialized = QByteArray("old-server-auth-key");
	auto config = MakeEnrollmentConfig();
	CHECK(config->dcOptions().markAuthorized(2));
	auto account = std::make_unique<Storage::Account>(
		basePath,
		key,
		std::move(config),
		false,
		[serialized] { return serialized; });
	CHECK(account->writeMtpConfig(true));
	CHECK(account->writeMtpData(true));

	CHECK(QDir().mkpath(basePath + u"future/nested"_q));
	CHECK(QDir().mkpath(basePath + u"database/future"_q));
	CHECK(QDir().mkpath(basePath + u"temp/future"_q));
	CHECK(QDir().mkpath(directory.path() + u"/tdata/tdld/future"_q));
	QFile futureStore(basePath + u"future/nested/messages"_q);
	CHECK(futureStore.open(QIODevice::WriteOnly));
	futureStore.write("server-scoped");
	futureStore.close();

	CHECK(account->writeServerReenrollmentTombstone());
	CHECK(account->serverReenrollmentPending());
	CHECK(account->completeServerReenrollment());
	CHECK(!account->serverReenrollmentPending());
	CHECK(ReadEnrollmentConfig(basePath, key) == nullptr);
	CHECK(!QFile::exists(basePath + u"future/nested/messages"_q));
	CHECK(!QDir(basePath + u"database"_q).exists());
	CHECK(!QDir(basePath + u"temp"_q).exists());
	CHECK(!QDir(directory.path() + u"/tdata/tdld"_q).exists());

	auto restored = QByteArray();
	auto restarted = MakeEnrollmentStorageAccount(
		basePath,
		key,
		[] { return QByteArray(); },
		[&](const QByteArray &value) { restored = value; });
	restarted->readMtpDataForTest();
	CHECK(restored.isEmpty());
}

TEST_CASE(ServerReenrollmentTombstoneReplaysAfterInterruption) {
	QTemporaryDir directory;
	CHECK(directory.isValid());

	const auto previousWorkingDir = QDir::currentPath();
	QDir::setCurrent(directory.path());
	const auto restoreWorkingDir = gsl::finally([&] {
		QDir::setCurrent(previousWorkingDir);
	});

	const auto basePath = directory.path() + u"account/"_q;
	const auto key = MakeEnrollmentStorageKey();
	const auto prepare = [&] {
		auto config = MakeEnrollmentConfig();
		CHECK(config->dcOptions().markAuthorized(2));
		auto account = std::make_unique<Storage::Account>(
			basePath,
			key,
			std::move(config),
			false,
			[] { return QByteArray("old-server-auth-key"); });
		CHECK(account->writeMtpConfig(true));
		CHECK(account->writeMtpData(true));
		CHECK(QDir().mkpath(basePath + u"future"_q));
		QFile futureStore(basePath + u"future/messages"_q);
		CHECK(futureStore.open(QIODevice::WriteOnly));
		futureStore.write("server-scoped");
		futureStore.close();
		CHECK(account->writeServerReenrollmentTombstone());
		return account;
	};

	for (const auto interruption : { 1, 2 }) {
		auto account = prepare();
		// The injected stop models a process kill at two different durable
		// boundaries. The next account instance is the next launch.
		account->setServerReenrollmentInterruptionForTest(interruption);
		CHECK(!account->completeServerReenrollment());
		CHECK(account->serverReenrollmentPending());
		account.reset();

		auto restored = QByteArray();
		auto restarted = MakeEnrollmentStorageAccount(
			basePath,
			key,
			[] { return QByteArray(); },
			[&](const QByteArray &value) { restored = value; });
		CHECK(restarted->serverReenrollmentPending());
		CHECK(restarted->completeServerReenrollment());
		CHECK(!restarted->serverReenrollmentPending());
		restarted->readMtpDataForTest();
		CHECK(restored.isEmpty());
	}
}

TEST_CASE(MtpAuthorizationLifecycleWriteSurvivesCleanAccountRestart) {
	QTemporaryDir directory;
	CHECK(directory.isValid());

	const auto previousWorkingDir = QDir::currentPath();
	QDir::setCurrent(directory.path());
	const auto restoreWorkingDir = gsl::finally([&] {
		QDir::setCurrent(previousWorkingDir);
	});

	const auto basePath = directory.path() + u"account/"_q;
	const auto key = MakeEnrollmentStorageKey();
	const auto serialized = QByteArray("persisted-auth-key");
	{
		auto config = MakeEnrollmentConfig();
		CHECK(config->dcOptions().markAuthorized(2));
		auto account = std::make_unique<Storage::Account>(
			basePath,
			key,
			std::move(config),
			false,
			[serialized] { return serialized; });
		// This is the mandatory synchronous seam used by Main::Account's
		// post-auth and clean-teardown paths.
		auto published = false;
		CHECK(Main::details::CommitPostAuthMtpAuthorization(
			account.get(),
			[&] { published = true; },
			[] {}));
		CHECK(published);
	}

	const auto restoredConfig = ReadEnrollmentConfig(basePath, key);
	CHECK(restoredConfig != nullptr);
	if (restoredConfig) {
		CHECK(restoredConfig->dcOptions().isAuthorized(2));
	}

	auto restored = QByteArray();
	{
		auto account = MakeEnrollmentStorageAccount(
			basePath,
			key,
			[] { return QByteArray(); },
			[&](const QByteArray &value) { restored = value; });
		account->readMtpDataForTest();
	}

	CHECK_EQ(restored, serialized);
}

TEST_CASE(PostAuthAuthorizationCommitFailureKeepsSessionClosed) {
	QTemporaryDir directory;
	CHECK(directory.isValid());

	const auto previousWorkingDir = QDir::currentPath();
	QDir::setCurrent(directory.path());
	const auto restoreWorkingDir = gsl::finally([&] {
		QDir::setCurrent(previousWorkingDir);
	});

	const auto basePath = directory.path() + u"account/"_q;
	auto writes = 0;
	auto account = MakeEnrollmentStorageAccount(
		basePath,
		MakeEnrollmentStorageKey(),
		nullptr,
		nullptr,
		[&] {
			++writes;
			return false;
		});
	auto published = false;
	auto failed = false;
	const auto result = Main::details::CommitPostAuthMtpAuthorization(
		account.get(),
		[&] { published = true; },
		[&] {
			failed = account->writeMtpAuthorizationFailure();
		});

	CHECK(!result);
	CHECK_EQ(writes, 1);
	CHECK(!published);
	CHECK(failed);
	CHECK(account->mtpAuthorizationWriteFailed());
	account.reset();

	auto restarted = MakeEnrollmentStorageAccount(
		basePath,
		MakeEnrollmentStorageKey());
	restarted->readMtpAuthorizationFailureMarkerForTest();
	CHECK(restarted->mtpAuthorizationWriteFailed());
}

TEST_CASE(CleanTeardownAuthorizationCommitFailureKeepsLastState) {
	QTemporaryDir directory;
	CHECK(directory.isValid());

	const auto previousWorkingDir = QDir::currentPath();
	QDir::setCurrent(directory.path());
	const auto restoreWorkingDir = gsl::finally([&] {
		QDir::setCurrent(previousWorkingDir);
	});

	const auto basePath = directory.path() + u"account/"_q;
	const auto key = MakeEnrollmentStorageKey();
	const auto serialized = QByteArray("last-durable-auth-key");
	auto account = MakeEnrollmentStorageAccount(
		basePath,
		key,
		[serialized] { return serialized; },
		nullptr,
		[] { return false; });
	CHECK(account->writeMtpConfig(true));
	CHECK(account->writeMtpData(true));

	auto published = false;
	auto blocked = false;
	const auto result = Main::details::CommitTeardownMtpAuthorization(
		account.get(),
		[&] { published = true; },
		[&] {
			blocked = account->writeMtpAuthorizationFailure();
			published = false;
		});

	CHECK(!result);
	CHECK(!published);
	CHECK(blocked);
	CHECK(account->mtpAuthorizationWriteFailed());
	account.reset();

	auto restored = QByteArray();
	auto restarted = MakeEnrollmentStorageAccount(
		basePath,
		key,
		[] { return QByteArray(); },
		[&](const QByteArray &value) { restored = value; });
	restarted->readMtpAuthorizationFailureMarkerForTest();
	CHECK(restarted->mtpAuthorizationWriteFailed());
	restarted->readMtpDataForTest();
	const auto config = ReadEnrollmentConfig(basePath, key);
	CHECK(config != nullptr);
	CHECK(config && config->hasCustomServer());
	CHECK_EQ(restored, serialized);
}

TEST_CASE(EnrollmentDoesNotResumeWhenProductionMapStorageFails) {
	QTemporaryDir directory;
	CHECK(directory.isValid());
	const auto basePath = directory.path() + QDir::separator();
	CHECK(QDir().mkpath(basePath + u"maps"_q));
	const auto key = MakeEnrollmentStorageKey();
	auto account = MakeEnrollmentStorageAccount(basePath, key);
	auto resumed = false;

	const auto committed = CommitServerEnrollment(
		[] { return true; },
		[&] { return account->writeMtpConfig(true); },
		[&] { resumed = true; });

	CHECK(!committed);
	CHECK(!resumed);
	CHECK(QDir(basePath + u"maps"_q).exists());
	CHECK(!QFile::exists(basePath + u"configs"_q));
}

TEST_CASE(EnrollmentDoesNotResumeWhenProductionConfigStorageFails) {
	QTemporaryDir directory;
	CHECK(directory.isValid());
	const auto basePath = directory.path() + QDir::separator();
	CHECK(QDir().mkpath(basePath + u"configs"_q));
	const auto key = MakeEnrollmentStorageKey();
	auto account = MakeEnrollmentStorageAccount(basePath, key);
	auto resumed = false;

	const auto committed = CommitServerEnrollment(
		[] { return true; },
		[&] { return account->writeMtpConfig(true); },
		[&] { resumed = true; });

	CHECK(!committed);
	CHECK(!resumed);
	CHECK(QDir(basePath + u"configs"_q).exists());
	CHECK(HasReadableEnrollmentMap(basePath, key));
}

TEST_CASE(EnrollmentDoesNotResumeWhileProductionPersistenceStalls) {
	QTemporaryDir directory;
	CHECK(directory.isValid());
	const auto basePath = directory.path() + QDir::separator();
	const auto key = MakeEnrollmentStorageKey();
	QSemaphore entered;
	QSemaphore release;
	auto resumed = std::atomic_bool(false);
	auto committed = std::atomic_bool(false);

	std::thread enrollment([&] {
		const auto result = CommitServerEnrollment(
			[] { return true; },
			[&] {
				entered.release();
				release.acquire();
				auto account = MakeEnrollmentStorageAccount(basePath, key);
				return account->writeMtpConfig(true);
			},
			[&] { resumed.store(true); });
		committed.store(result);
	});

	CHECK(entered.tryAcquire(1, 1000));
	CHECK(!resumed.load());
	CHECK(!committed.load());

	release.release();
	enrollment.join();
	CHECK(committed.load());
	CHECK(resumed.load());
}

TEST_CASE(EnrollmentStepConsumesSpaceOutsideConfirm) {
	// Exercise the same QKeyEvent gate used by ServerKeyWidget::keyPressEvent.
	auto enter = QKeyEvent(
		QEvent::KeyPress,
		Qt::Key_Enter,
		Qt::NoModifier);
	CHECK(ConsumeServerEnrollmentActivationKey(enter));
	CHECK(enter.isAccepted());

	auto returnKey = QKeyEvent(
		QEvent::KeyPress,
		Qt::Key_Return,
		Qt::NoModifier);
	CHECK(ConsumeServerEnrollmentActivationKey(returnKey));
	CHECK(returnKey.isAccepted());

	auto space = QKeyEvent(
		QEvent::KeyPress,
		Qt::Key_Space,
		Qt::NoModifier);
	CHECK(ConsumeServerEnrollmentActivationKey(space));
	CHECK(space.isAccepted());

	auto tab = QKeyEvent(
		QEvent::KeyPress,
		Qt::Key_Tab,
		Qt::NoModifier);
	tab.ignore();
	CHECK(!ConsumeServerEnrollmentActivationKey(tab));
	CHECK(!tab.isAccepted());
}

TEST_CASE(QueuedStopRunsOnlyForTheCurrentEnrollment) {
	// Session::stopUntilPinChange() uses this production queue to cross into
	// the session thread after taking the account-side generation token.
	QThread sessionThread;
	sessionThread.start();
	auto target = std::make_unique<QObject>();
	target->moveToThread(&sessionThread);

	auto currentToken = uint64(7);
	auto stopped = std::atomic_int(0);
	QSemaphore callbackDone;

	QueueServerEnrollmentStop(
		target.get(),
		uint64(6),
		[&](uint64 token) { return token == currentToken; },
		[&] {
			stopped.fetch_add(1);
			callbackDone.release();
		});
	CHECK(!callbackDone.tryAcquire(1, 50));
	CHECK_EQ(stopped.load(), 0);

	QueueServerEnrollmentStop(
		target.get(),
		currentToken,
		[&](uint64 token) { return token == currentToken; },
		[&] {
			stopped.fetch_add(1);
			callbackDone.release();
		});
	CHECK(callbackDone.tryAcquire(1, 1000));
	CHECK_EQ(stopped.load(), 1);

	const auto mainThread = QCoreApplication::instance()->thread();
	QMetaObject::invokeMethod(
		target.get(),
		[targetPtr = target.get(), mainThread] {
			targetPtr->moveToThread(mainThread);
		},
		Qt::BlockingQueuedConnection);
	sessionThread.quit();
	sessionThread.wait();
}

} // namespace
