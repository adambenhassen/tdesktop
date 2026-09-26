/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "boxes/peers/edit_peer_common.h"

#include <functional>

namespace {

using Ui::EditPeer::UsernameEditorFlow;
using FailureResult = UsernameEditorFlow::FailureResult;
using Status = UsernameEditorFlow::Status;

class ControlledUsernameApi final {
public:
	[[nodiscard]] bool check(
			UsernameEditorFlow &flow,
			const QString &username,
			bool force = false,
			bool trackAvailability = true) {
		return flow.check(
			username,
			force,
			trackAvailability,
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
	[[nodiscard]] bool update(
			UsernameEditorFlow &flow,
			bool requireGood,
			Save save) {
		return flow.trySave(
			requireGood,
			[this, save = std::move(save)](const QString &username) {
			++updates;
			updatedUsername = username;
			save(username);
			});
	}

	int checks = 0;
	int failureCallbacks = 0;
	int updates = 0;
	QString checkedUsername;
	QString updatedUsername;
	FailureResult lastFailure = FailureResult::Handled;
	bool failureWasCurrent = false;

private:
	std::function<void(bool)> _done;
	std::function<void(const QString &)> _fail;
};

TEST_CASE(UsernameEditorFlowDiscardsLateAvailabilityAfterInputChanges) {
	UsernameEditorFlow flow;
	ControlledUsernameApi api;
	flow.inputChanged(u"Ab"_q, true);
	if (!api.check(flow, u"Ab"_q)) {
		CHECK(false);
		return;
	}

	flow.inputChanged(u"A"_q, false);

	api.succeed(true);
	CHECK(!flow.good());
	CHECK(flow.status() == Status::Error);
}

TEST_CASE(AccountUsernameEditorFallbackSendsUpdateWithoutRepeatCheck) {
	UsernameEditorFlow flow;
	ControlledUsernameApi api;

	flow.inputChanged(u"Ab"_q, true);
	if (!api.check(flow, u"Ab"_q)) {
		CHECK(false);
		return;
	}
	api.fail(u"INPUT_METHOD_INVALID"_q);
	CHECK(api.lastFailure == FailureResult::Unavailable);
	CHECK(api.failureWasCurrent);
	CHECK(flow.status() == Status::Unavailable);

	flow.inputChanged(u"A"_q, false);
	CHECK(flow.status() == Status::Unavailable);
	CHECK(!api.check(flow, u"A"_q));
	CHECK_EQ(api.checks, 1);

	flow.inputChanged(u"Cd"_q, true);
	CHECK(flow.status() == Status::Unavailable);
	CHECK(!api.check(flow, u"Cd"_q));
	CHECK_EQ(api.checks, 1);
	CHECK(api.update(flow, false, [](const QString &) {}));
	CHECK_EQ(api.updates, 1);
	CHECK_EQ(api.updatedUsername, u"Cd"_q);
}

TEST_CASE(GroupChannelFallbackRejectsShortAndSavesValidEdit) {
	UsernameEditorFlow flow;
	ControlledUsernameApi api;

	flow.inputChanged(u"Ab"_q, true);
	if (!api.check(flow, u"Ab"_q)) {
		CHECK(false);
		return;
	}
	api.fail(u"INPUT_METHOD_INVALID"_q);
	CHECK(api.lastFailure == FailureResult::Unavailable);

	flow.inputChanged(u"A"_q, false);
	CHECK(flow.status() == Status::Unavailable);
	CHECK(!api.check(flow, u"A"_q));
	CHECK(!api.update(flow, true, [](const QString &) {}));
	CHECK_EQ(api.checks, 1);
	CHECK_EQ(api.updates, 0);

	flow.inputChanged(u"Cd"_q, true);
	CHECK(flow.status() == Status::Unavailable);
	CHECK(!api.check(flow, u"Cd"_q));
	CHECK(api.update(flow, true, [](const QString &) {}));
	CHECK_EQ(api.checks, 1);
	CHECK_EQ(api.updates, 1);
	CHECK_EQ(api.updatedUsername, u"Cd"_q);
}

TEST_CASE(UsernameEditorFlowIgnoresStaleOrdinaryFailure) {
	UsernameEditorFlow flow;
	ControlledUsernameApi api;
	flow.inputChanged(u"Ab"_q, true);
	if (!api.check(flow, u"Ab"_q)) {
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
	UsernameEditorFlow flow;
	ControlledUsernameApi api;
	flow.inputChanged(u"Ab"_q, true);
	if (!api.check(flow, u"Ab"_q)) {
		CHECK(false);
		return;
	}
	flow.inputChanged(u"A"_q, false);

	api.fail(u"INPUT_METHOD_INVALID"_q);
	CHECK_EQ(api.failureCallbacks, 1);
	CHECK(api.lastFailure == FailureResult::Unavailable);
	CHECK(!api.failureWasCurrent);
	CHECK(flow.status() == Status::Unavailable);
	CHECK(!api.check(flow, u"A"_q));
	CHECK(!api.update(flow, true, [](const QString &) {}));
	CHECK_EQ(api.checks, 1);
	CHECK_EQ(api.updates, 0);
}

} // namespace
