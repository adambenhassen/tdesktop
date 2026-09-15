/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/account_lifecycle_regression.h"

#include "core/application.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session_settings.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/mtproto_config.h"
#include "storage/storage_account.h"
#include "storage/storage_domain.h"

#include <QtCore/QByteArray>
#include <QtCore/QCoreApplication>

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

[[nodiscard]] std::shared_ptr<MTP::details::RSAPublicKey>
RegressionServerKey() {
	return std::make_shared<MTP::details::RSAPublicKey>(bytes::make_span(
		kRegressionServerKey,
		sizeof(kRegressionServerKey) - 1));
}

[[nodiscard]] bool ConfigurePinnedServer(not_null<Main::Account*> account) {
	const auto configured = account->mtp().dcOptions().setCustomServer(
		MTP::CustomServer{
			.dcId = 2,
			.ip = "127.0.0.1",
			.port = 8443,
			.key = RegressionServerKey(),
		});
	return configured && account->local().writeMtpConfig(true);
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

} // namespace

int RunAccountLifecycleRegression() {
	const auto failureVariable = QByteArray(
		"TDESKTOP_FAIL_MTP_AUTHORIZATION_WRITE");
	const auto failWrites = gsl::finally([&] {
		qunsetenv(failureVariable.constData());
	});

	auto &domain = Core::App().domain();
	if (!domain.started()) {
		return 1;
	}

	// This is the production post-auth caller. It must keep the session
	// unpublished when the synchronous authorization write is refused.
	const auto account = not_null<Main::Account*>(
		domain.accounts().front().account.get());
	if (!ConfigurePinnedServer(account)) {
		return 1;
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
		return 1;
	}

	// Clear the post-auth marker while the real Main::Account is still alive.
	// Its destructor must then recreate the marker through the clean-teardown
	// caller, leaving the same account fail closed on the next start.
	account->local().clearCustomServerBlocked();
	if (const auto window = Core::App().activePrimaryWindow()) {
		Core::App().closeWindow(window);
	}
	domain.local().writeAccounts();
	domain.finish();
	if (domain.start(QByteArray()) != Storage::StartResult::Success) {
		return 1;
	}

	const auto blocked = FindAuthorizationBlockedAccount(domain);
	return (blocked && blocked->mtp().config().blocked()) ? 0 : 1;
}

} // namespace Tests
