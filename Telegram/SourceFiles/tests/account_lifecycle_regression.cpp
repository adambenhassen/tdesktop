/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/account_lifecycle_regression.h"

#include "apiwrap.h"
#include "core/application.h"
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
#include "storage/storage_account.h"
#include "storage/storage_domain.h"

#include <QtCore/QByteArray>
#include <QtCore/QCoreApplication>
#include <QtCore/QEventLoop>
#include <QtCore/QFileInfo>
#include <QtCore/QMetaObject>
#include <QtCore/QTimer>

#include <algorithm>
#include <cstdio>

namespace Tests {
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

[[nodiscard]] bool RestartDomain(Main::Domain &domain) {
	domain.local().writeAccounts();
	domain.finish();
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

[[nodiscard]] bool CachePayloadMatches(
		Storage::Cache::Database &cache,
		const Storage::Cache::Key &key,
		const QByteArray &expected) {
	auto completed = false;
	auto payload = QByteArray();
	auto loop = QEventLoop();
	auto timeout = QTimer();
	timeout.setSingleShot(true);
	QObject::connect(
		&timeout,
		&QTimer::timeout,
		&loop,
		&QEventLoop::quit);
	cache.get(key, [&](QByteArray &&value) {
		payload = std::move(value);
		completed = true;
		QMetaObject::invokeMethod(&loop, "quit", Qt::QueuedConnection);
	});
	timeout.start(5000);
	loop.exec();
	return completed && (payload == expected);
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
	const auto cachePath = account->local().cachePath();
	{
		auto cacheDatabase = Core::App().databases().get(
			cachePath,
			account->local().cacheSettings());
		cacheDatabase->put(cacheKey, QByteArray(cachePayload));
		if (!CachePayloadMatches(*cacheDatabase, cacheKey, cachePayload)
			|| !QFileInfo::exists(cachePath)) {
			return FailAccountLifecycleRegression(
				"could not seed the cache payload");
		}
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

	if (!RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"could not restart after Forget");
	}
	const auto forgotten = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	auto cacheDatabase = Core::App().databases().get(
		cachePath,
		forgotten->local().cacheSettings());
	if (!QFileInfo::exists(cachePath)
		|| !CachePayloadMatches(*cacheDatabase, cacheKey, cachePayload)
		|| !forgotten->mtp().dcOptions().unenrolled()
		|| forgotten->mtp().dcOptions().blocked()
		|| forgotten->local().hasStoredCustomServer()
		|| forgotten->local().mtpAuthorizationWriteFailed()
		|| forgotten->willHaveSessionUniqueId(nullptr) != 0
		|| !forgotten->mtp().dcOptions().configEnumDcIds().empty()
		|| forgotten->local().mtpAuthorizationDataExistsForRegressionTest()) {
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
	if (!RestartDomain(domain)) {
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
	if (!Main::details::CommitServerForget(
			&failedTeardown->local(),
			Storage::ServerCacheBinding{
				.fingerprintKnown = true,
				.fingerprint = originalFingerprint,
				.userIdKnown = true,
				.userId = 4242,
			},
			[] {})
		|| !RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"could not return to enrollment after teardown block");
	}
	auto unenrolled = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (!unenrolled->mtp().dcOptions().unenrolled()
		|| unenrolled->local().mtpAuthorizationWriteFailed()
		|| unenrolled->local().mtpAuthorizationDataExistsForRegressionTest()
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
		|| unenrolled->local().mtpAuthorizationDataExistsForRegressionTest()) {
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
	if (!QFileInfo::exists(cachePath)
		|| !CachePayloadMatches(*cacheDatabase, cacheKey, cachePayload)) {
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
	if (!QFileInfo::exists(cachePath)
		|| !CachePayloadMatches(*cacheDatabase, cacheKey, cachePayload)) {
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
		|| unenrolled->local().mtpAuthorizationDataExistsForRegressionTest()
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
		|| blockedWithoutAuthorizationFailure->local().mtpAuthorizationDataExistsForRegressionTest()) {
		return FailAccountLifecycleRegression(
			"synthetic blocked startup did not retain its empty auth state");
	}
	if (!RestartDomain(domain)) {
		return FailAccountLifecycleRegression(
			"blocked teardown did not complete its restart");
	}
	blockedWithoutAuthorizationFailure = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (!blockedWithoutAuthorizationFailure->mtp().config().blocked()
		|| blockedWithoutAuthorizationFailure->local().mtpAuthorizationWriteFailed()
		|| blockedWithoutAuthorizationFailure->local().mtpAuthorizationDataExistsForRegressionTest()) {
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
