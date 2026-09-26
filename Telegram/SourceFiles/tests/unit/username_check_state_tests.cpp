/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "boxes/peers/edit_peer_common.h"

namespace {

using Ui::EditPeer::UsernameCheckState;

TEST_CASE(UsernameCheckDiscardsLateAvailabilityAfterInputChanges) {
	UsernameCheckState state;
	state.inputChanged(u"Ab"_q, true);
	const auto request = state.requestStarted();

	state.inputChanged(u"A"_q, false);

	CHECK(!state.setAvailability(request, true));
	CHECK(!state.good());
}

TEST_CASE(UsernameCheckUnavailableAllowsValidEditsWithoutMoreRequests) {
	UsernameCheckState state;
	state.inputChanged(u"Ab"_q, true);
	const auto request = state.requestStarted();

	CHECK(state.isCurrent(request));
	state.markUnavailable();
	CHECK(state.unavailable());

	state.inputChanged(u"Ab"_q, true);
	CHECK(state.good());
	CHECK(!state.shouldCheck());

	state.inputChanged(u"A"_q, false);
	CHECK(!state.good());
	CHECK(!state.shouldCheck());

	state.inputChanged(u"Cd"_q, true);
	CHECK(state.good());
	CHECK(!state.shouldCheck());
}

} // namespace
