/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "boxes/peers/edit_peer_common.h"

#include <functional>
#include <initializer_list>
#include <utility>

namespace {

using Ui::EditPeer::UsernameEditorFlow;
using FailureResult = UsernameEditorFlow::FailureResult;
using Mode = UsernameEditorFlow::Mode;
using Status = UsernameEditorFlow::Status;

class ControlledUsernameApi final {
public:
	enum class Update {
		None,
		Account,
		Channel,
	};

	[[nodiscard]] bool checkAccount(
			UsernameEditorFlow &flow,
			const QString &username) {
		return flow.checkAccount(
			username,
			[this](
					const QString &checking,
					auto done,
					auto fail) {
			++checks;
			checkedUsername = checking;
			_done = std::move(done);
			_fail = std::move(fail);
		},
			[](bool) {
		},
			[this](
					const QString &,
					FailureResult result,
					bool current) {
			++failureCallbacks;
			lastFailure = result;
			failureWasCurrent = current;
		});
	}

	[[nodiscard]] bool checkPeer(
			UsernameEditorFlow &flow,
			const QString &username,
			bool initial = false) {
		return flow.checkPublicPeer(
			username,
			initial,
			[this](
					const QString &checking,
					auto done,
					auto fail) {
			++checks;
			checkedUsername = checking;
			_done = std::move(done);
			_fail = std::move(fail);
		},
			[](bool) {
		},
			[this](
					const QString &,
					FailureResult result,
					bool current) {
			++failureCallbacks;
			lastFailure = result;
			failureWasCurrent = current;
		});
	}

	void fail(const QString &error) {
		_fail(error);
	}

	void succeed(bool available) {
		_done(available);
	}

	template <typename Save>
	[[nodiscard]] bool updateAccount(
			UsernameEditorFlow &flow,
			Save save) {
		return flow.saveAccount(
			[this, save = std::move(save)](const QString &username) {
			++updates;
			updatedUsername = username;
			lastUpdate = Update::Account;
			updateRequestSent = true;
			save(username);
			});
	}

	template <typename Save>
	[[nodiscard]] bool updatePeer(
			UsernameEditorFlow &flow,
			Save save) {
		return flow.savePublicPeer(
			[this, save = std::move(save)](const QString &username) {
			++updates;
			updatedUsername = username;
			lastUpdate = Update::Channel;
			updateRequestSent = true;
			save(username);
			});
	}

	int checks = 0;
	int failureCallbacks = 0;
	int updates = 0;
	QString checkedUsername;
	QString updatedUsername;
	Update lastUpdate = Update::None;
	bool updateRequestSent = false;
	FailureResult lastFailure = FailureResult::Handled;
	bool failureWasCurrent = false;

private:
	std::function<void(bool)> _done;
	std::function<void(const QString &)> _fail;

};

TEST_CASE(UsernameEditorFlowDiscardsLateAvailabilityAfterInputChanges) {
	UsernameEditorFlow flow(Mode::Group);
	ControlledUsernameApi api;
	flow.inputChanged(u"Ab"_q, true);
	if (!api.checkPeer(flow, u"Ab"_q)) {
		CHECK(false);
		return;
	}

	flow.inputChanged(u"A"_q, false);

	api.succeed(true);
	CHECK(!flow.good());
	CHECK(flow.status() == Status::Error);
}

TEST_CASE(ProfileFlowFallbackSendsUpdateWithoutRepeatCheck) {
	UsernameEditorFlow flow(Mode::Profile);
	ControlledUsernameApi api;

	flow.inputChanged(u"Ab"_q, true);
	if (!api.checkAccount(flow, u"Ab"_q)) {
		CHECK(false);
		return;
	}
	CHECK_EQ(api.checkedUsername, u"Ab"_q);
	api.fail(u"INPUT_METHOD_INVALID"_q);
	CHECK(api.lastFailure == FailureResult::Unavailable);
	CHECK(api.failureWasCurrent);
	CHECK(flow.status() == Status::Unavailable);
	CHECK(!flow.shouldCheck());

	flow.inputChanged(u"A"_q, false);
	CHECK(flow.status() == Status::Error);
	CHECK(!api.checkAccount(flow, u"A"_q));
	CHECK_EQ(api.checks, 1);

	flow.inputChanged(u"Cd"_q, true);
	CHECK(flow.status() == Status::Unavailable);
	CHECK(!api.checkAccount(flow, u"Cd"_q));
	CHECK_EQ(api.checks, 1);
	CHECK(api.updateAccount(flow, [](const QString &) {}));
	CHECK_EQ(api.updates, 1);
	CHECK_EQ(api.updatedUsername, u"Cd"_q);
	CHECK(api.updateRequestSent);
	CHECK(api.lastUpdate == ControlledUsernameApi::Update::Account);
}

TEST_CASE(GroupChannelFallbackRejectsShortAndSavesValidEdit) {
	for (const auto mode : { Mode::Group, Mode::Channel }) {
		UsernameEditorFlow flow(mode);
		ControlledUsernameApi api;

		flow.inputChanged(u"Ab"_q, true);
		if (!api.checkPeer(flow, u"Ab"_q)) {
			CHECK(false);
			continue;
		}
		CHECK_EQ(api.checkedUsername, u"Ab"_q);
		api.fail(u"INPUT_METHOD_INVALID"_q);
		CHECK(api.lastFailure == FailureResult::Unavailable);
		CHECK(flow.status() == Status::Unavailable);
		CHECK(!flow.shouldCheck());

		flow.inputChanged(u"A"_q, false);
		CHECK(flow.status() == Status::Error);
		CHECK(!api.checkPeer(flow, u"A"_q));
		CHECK(!api.updatePeer(flow, [](const QString &) {}));
		CHECK_EQ(api.checks, 1);
		CHECK_EQ(api.updates, 0);
		CHECK(!api.updateRequestSent);

		flow.inputChanged(u"Cd"_q, true);
		CHECK(flow.status() == Status::Unavailable);
		CHECK(!api.checkPeer(flow, u"Cd"_q));
		CHECK(api.updatePeer(flow, [](const QString &) {}));
		CHECK_EQ(api.checks, 1);
		CHECK_EQ(api.updates, 1);
		CHECK_EQ(api.updatedUsername, u"Cd"_q);
		CHECK(api.updateRequestSent);
		CHECK(api.lastUpdate == ControlledUsernameApi::Update::Channel);
	}
}

TEST_CASE(PublicUsernameCanBeRecheckedAfterPrivacyToggle) {
	CHECK(Ui::EditPeer::IsValidPublicUsername(u"Ab"_q));
	CHECK(!Ui::EditPeer::IsValidPublicUsername(u"A"_q));

	for (const auto mode : { Mode::Group, Mode::Channel }) {
		UsernameEditorFlow flow(mode);
		ControlledUsernameApi api;

		flow.inputChanged(u"Ab"_q, true);
		flow.setGood(true);
		if (!api.checkPeer(flow, u"Ab"_q)) {
			CHECK(false);
			continue;
		}

		flow.inputChanged(u"Ab"_q, false);
		api.succeed(true);
		CHECK(!flow.good());
		CHECK(!api.updatePeer(flow, [](const QString &) {}));
		CHECK_EQ(api.updates, 0);
		auto wasRefreshed = false;
		auto checkStarted = false;
		flow.revalidatePublicUsername(
			u"Ab"_q,
			Ui::EditPeer::IsValidPublicUsername(u"Ab"_q),
			[&] { wasRefreshed = true; },
			[&] { checkStarted = api.checkPeer(flow, u"Ab"_q); });
		CHECK(wasRefreshed);
		CHECK(checkStarted);
		CHECK_EQ(api.checks, 2);
		CHECK_EQ(api.checkedUsername, u"Ab"_q);

		api.succeed(true);
		CHECK(flow.good());
		CHECK(api.updatePeer(flow, [](const QString &) {}));
		CHECK_EQ(api.updatedUsername, u"Ab"_q);
		CHECK_EQ(api.updates, 1);
		CHECK(api.updateRequestSent);
	}
}

TEST_CASE(UsernameEditorFlowIgnoresStaleOrdinaryFailure) {
	UsernameEditorFlow flow(Mode::Group);
	ControlledUsernameApi api;
	flow.inputChanged(u"Ab"_q, true);
	if (!api.checkPeer(flow, u"Ab"_q)) {
		CHECK(false);
		return;
	}
	flow.inputChanged(u"A"_q, false);

	api.fail(u"USERNAME_OCCUPIED"_q);
	CHECK_EQ(api.failureCallbacks, 0);
	CHECK(!flow.unavailable());
	CHECK(flow.status() == Status::Error);
}

TEST_CASE(UsernameEditorFlowHandlesStaleUnavailableResponse) {
	UsernameEditorFlow flow(Mode::Group);
	ControlledUsernameApi api;
	flow.inputChanged(u"Ab"_q, true);
	if (!api.checkPeer(flow, u"Ab"_q)) {
		CHECK(false);
		return;
	}
	flow.inputChanged(u"A"_q, false);

	api.fail(u"INPUT_METHOD_INVALID"_q);
	CHECK_EQ(api.failureCallbacks, 1);
	CHECK(api.lastFailure == FailureResult::Unavailable);
	CHECK(!api.failureWasCurrent);
	CHECK(flow.status() == Status::Unavailable);
	CHECK(!flow.shouldCheck());
	flow.inputChanged(u"A"_q, false);
	CHECK(flow.status() == Status::Error);
	CHECK(!api.checkPeer(flow, u"A"_q));
	CHECK(!api.updatePeer(flow, [](const QString &) {}));
	CHECK_EQ(api.checks, 1);
	CHECK_EQ(api.updates, 0);
	CHECK(!api.updateRequestSent);
}

} // namespace
