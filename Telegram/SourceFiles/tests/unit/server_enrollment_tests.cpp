/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "mtproto/mtp_instance.h"
#include "mtproto/mtproto_server_enrollment.h"
#include "mtproto/session.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QMetaObject>
#include <QtCore/QSemaphore>
#include <QtCore/QThread>
#include <QtCore/Qt>
#include <QtGui/QKeyEvent>

#include <atomic>
#include <memory>
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
