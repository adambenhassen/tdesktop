/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "mtproto/mtp_instance.h"
#include "mtproto/mtproto_server_enrollment.h"

#include <QtCore/Qt>

#include <vector>

namespace {

using namespace MTP;

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
		[&] { persisted = true; },
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

TEST_CASE(RejectedEnrollmentDoesNotReachNetworkOrAuth) {
	auto networkCalls = 0;
	auto authCalls = 0;
	const auto committed = CommitServerEnrollment(
		[] { return false; },
		[&] { ++networkCalls; },
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
		[&] { events.push_back(2); }, // persist the pin
		[&] { events.push_back(3); }); // start network and auth

	CHECK(committed);
	CHECK_EQ(int(events.size()), 3);
	CHECK_EQ(events[0], 1);
	CHECK_EQ(events[1], 2);
	CHECK_EQ(events[2], 3);
}

TEST_CASE(EnrollmentStepConsumesSpaceOutsideConfirm) {
	CHECK(IsServerEnrollmentActivationKey(int(Qt::Key_Enter)));
	CHECK(IsServerEnrollmentActivationKey(int(Qt::Key_Return)));
	CHECK(IsServerEnrollmentActivationKey(int(Qt::Key_Space)));
	CHECK(!IsServerEnrollmentActivationKey(int(Qt::Key_Tab)));
}

} // namespace
