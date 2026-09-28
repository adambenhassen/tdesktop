/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "api/api_updates.h"
#include "data/data_pts_waiter.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/mtproto_dc_options.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QThread>

namespace {

using namespace MTP;

[[nodiscard]] PinnedServerFailureReport Report(
		ShiftedDcId shiftedDcId,
		PinnedServerFailure failure,
		uint64 pinnedFingerprint = 0,
		uint64 presentedFingerprint = 0) {
	return {
		shiftedDcId,
		failure,
		pinnedFingerprint,
		presentedFingerprint,
	};
}

// Collects every value the channel emits from now on. The initial
// held value counts as an emission: a late subscriber has to see it.
class Emissions {
public:
	explicit Emissions(PinnedServerFailureChannel &channel) {
		channel.updates() | rpl::on_next([=](
				std::optional<PinnedServerFailureReport> value) {
			_values.push_back(std::move(value));
		}, _lifetime);
	}

	[[nodiscard]] int count() const {
		return int(_values.size());
	}
	[[nodiscard]] const std::optional<PinnedServerFailureReport> &at(
			int index) const {
		return _values[index];
	}

private:
	std::vector<std::optional<PinnedServerFailureReport>> _values;
	rpl::lifetime _lifetime;

};

} // namespace

// The swallow finding: a repeated identical failure must emit again.
// A compare-then-assign holder would drop the second emission, and a
// step that cleared its error label on navigation would then show
// nothing while the session is stopped a second time.
TEST_CASE(RepeatedIdenticalFailureEmitsAgain) {
	PinnedServerFailureChannel channel;
	const auto report = Report(2, PinnedServerFailure::KeyMismatch);
	channel.report(report);
	Emissions emissions(channel);
	channel.report(report);
	CHECK_EQ(emissions.count(), 2);
	CHECK(emissions.at(1) == report);
}

// A late subscriber starts from the held report, not from nothing.
TEST_CASE(LateSubscriberSeesHeldReport) {
	PinnedServerFailureChannel channel;
	const auto report = Report(2, PinnedServerFailure::DcIdMismatch);
	channel.report(report);
	Emissions emissions(channel);
	CHECK_EQ(emissions.count(), 1);
	CHECK(emissions.at(0) == report);
	CHECK(channel.current().has_value());
}

TEST_CASE(PinnedServerFailureKeepsBothFingerprints) {
	const auto report = Report(
		2,
		PinnedServerFailure::KeyMismatch,
		123,
		456);
	PinnedServerFailureChannel channel;
	channel.report(report);

	CHECK(channel.current().has_value());
	CHECK_EQ(channel.current()->pinnedFingerprint, uint64(123));
	CHECK_EQ(channel.current()->presentedFingerprint, uint64(456));
}

TEST_CASE(AuthorizedKeyMismatchUsesTheIdentityChangeFlow) {
	const auto mismatch = Report(2, PinnedServerFailure::KeyMismatch);
	const auto dcMismatch = Report(2, PinnedServerFailure::DcIdMismatch);

	CHECK(MTP::ShouldShowPinnedServerIdentityChange(mismatch, true, true));
	CHECK(!MTP::ShouldShowPinnedServerIdentityChange(mismatch, false, true));
	CHECK(!MTP::ShouldShowPinnedServerIdentityChange(mismatch, true, false));
	CHECK(!MTP::ShouldShowPinnedServerIdentityChange(dcMismatch, true, true));
}

// The clear side: only the reporting session's own successful
// connection retires the report. Another session of the same DC -
// same bare id, different shift - retires nothing.
TEST_CASE(RetireMatchesTheReportingSessionOnly) {
	PinnedServerFailureChannel channel;
	const auto main = ShiftedDcId(2);
	const auto shifted = ShiftDcId(2, 1);
	channel.report(Report(main, PinnedServerFailure::DcIdMismatch));
	Emissions emissions(channel);

	// Subscribing delivers the held report itself.
	CHECK_EQ(emissions.count(), 1);
	CHECK(emissions.at(0).has_value());

	channel.retireIfReportedBy(shifted);
	CHECK_EQ(emissions.count(), 1);
	CHECK(channel.current().has_value());

	channel.retireIfReportedBy(main);
	CHECK(!channel.current().has_value());
	CHECK_EQ(emissions.count(), 2);
	CHECK(!emissions.at(1).has_value());

	// Retiring twice reports once.
	channel.retireIfReportedBy(main);
	CHECK_EQ(emissions.count(), 2);
}

// Retiring an empty channel is a no-op that emits nothing.
TEST_CASE(RetireWithoutAReportIsANoop) {
	PinnedServerFailureChannel channel;
	Emissions emissions(channel);
	channel.retireIfReportedBy(2);
	CHECK_EQ(emissions.count(), 1); // only the initial empty value
	CHECK(!channel.current().has_value());
}

// Pausing an instance invalidates callbacks immediately. Incrementing only
// when resume() runs leaves a late resolver or timer callback looking current
// during the entire enrollment pause.
TEST_CASE(PausingEnrollmentInvalidatesTheCurrentGeneration) {
	ServerEnrollmentGate gate;
	CHECK(gate.start());
	const auto beforePause = gate.stopToken();

	CHECK(gate.pause());
	CHECK(!gate.stopTokenIsCurrent(beforePause));
	CHECK(!gate.networkAllowed());

	const auto whilePaused = gate.stopToken();
	CHECK(gate.resume().resumed);
	CHECK(!gate.stopTokenIsCurrent(whilePaused));
	CHECK(gate.networkAllowed());
}

// An untrusted delegated background value must not reach the special-config
// loader when production fallback is refused. Count the observable request
// boundary rather than relying on the loader implementation being a no-op.
TEST_CASE(RefusedFallbackSkipsHttpTimeSpecialConfigIo) {
	auto options = DcOptions(Environment::Production);
	options.constructUnenrolled();
	const auto unsafeDelegatedUrl = u"https://updates.attacker.test"_q;
	auto specialConfigIoAttempts = 0;

	if (CanStartSpecialConfigRequest(
			unsafeDelegatedUrl,
			true,
			false,
			false,
			options.refusesProductionFallback())) {
		++specialConfigIoAttempts;
	}

	CHECK_EQ(specialConfigIoAttempts, 0);
}

TEST_CASE(StaleStateReplyCannotApplyAfterFreshRequestStarts) {
	using Type = Api::details::UpdateRequestState::Type;
	auto requests = Api::details::UpdateRequestState();
	auto applied = 0;
	requests.started(Type::State, 41);
	requests.clearInactive([](mtpRequestId) { return false; });
	requests.started(Type::State, 42);
	CHECK(!requests.finish(Type::State, 41, [&] { ++applied; }));
	CHECK(requests.pending());
	CHECK(requests.finish(Type::State, 42, [&] { ++applied; }));
	CHECK_EQ(applied, 1);
	CHECK(!requests.pending());
}

TEST_CASE(EnrollmentPausedFailureHasTerminalLocalIdentity) {
	const auto error = MTP::Error::Local(
		"SERVER_ENROLLMENT_PAUSED",
		"Network access is paused until server enrollment completes.");
	CHECK_EQ(error.code(), MTP::Error::NoError);
	CHECK(MTP::IsServerEnrollmentPausedError(error));
	CHECK(!MTP::IsServerEnrollmentPausedError(
		MTP::Error::Local("RESPONSE_PARSE_FAILED", "Empty response.")));
}

TEST_CASE(CancelledEnrollmentRefusalDoesNotDeliver) {
	auto refusals = MTP::ServerEnrollmentRefusalQueue();
	auto delivered = 0;
	auto callbacks = MTP::ResponseHandler{
		nullptr,
		[&](const MTP::Error &, const MTP::Response &) {
			++delivered;
			return true;
		},
	};
	CHECK(refusals.reject(false, 61, callbacks));
	CHECK(refusals.pending(61));
	refusals.cancel(61);
	CHECK(!refusals.pending(61));
	QCoreApplication::processEvents();
	CHECK_EQ(delivered, 0);
}

TEST_CASE(LiveEnrollmentRefusalDeliversExactlyOnce) {
	auto refusals = MTP::ServerEnrollmentRefusalQueue();
	auto delivered = 0;
	auto callbacks = MTP::ResponseHandler{
		nullptr,
		[&](const MTP::Error &error, const MTP::Response &response) {
			CHECK(MTP::IsServerEnrollmentPausedError(error));
			CHECK_EQ(response.requestId, mtpRequestId(62));
			++delivered;
			return true;
		},
	};
	CHECK(refusals.reject(false, 62, callbacks));
	CHECK(refusals.pending(62));
	QCoreApplication::processEvents();
	QCoreApplication::processEvents();
	CHECK_EQ(delivered, 1);
	CHECK(!refusals.pending(62));
}

TEST_CASE(DestroyedEnrollmentRefusalQueueDropsDelivery) {
	auto delivered = 0;
	{
		auto refusals = MTP::ServerEnrollmentRefusalQueue();
		auto callbacks = MTP::ResponseHandler{
			nullptr,
			[&](const MTP::Error &, const MTP::Response &) {
				++delivered;
				return true;
			},
		};
		CHECK(refusals.reject(false, 63, callbacks));
	}
	QCoreApplication::processEvents();
	CHECK_EQ(delivered, 0);
}

TEST_CASE(ContiguousUpdateAfterEnrollmentRecoveryAppliesOnce) {
	auto applied = 0;
	auto waiter = PtsWaiter({
		.startTimer = [](ChannelData *, crl::time) {},
		.applyUpdate = [&](const MTPUpdate &) { ++applied; },
		.applyUpdates = [](const MTPUpdates &) {},
	});
	waiter.init(7);
	waiter.setRequesting(false);
	const auto update = MTP_updateDeleteMessages(
		MTP_vector<MTPint>(),
		MTP_int(8),
		MTP_int(1));
	CHECK(waiter.updateAndApply(nullptr, 8, 1, update));
	CHECK(!waiter.updateAndApply(nullptr, 8, 1, update));
	CHECK_EQ(applied, 1);
	CHECK_EQ(waiter.current(), 8);
}

TEST_CASE(EnrollmentResumeEventsAreInstanceScopedAndLifetimeBound) {
	auto first = MTP::ServerEnrollmentGate(true);
	auto second = MTP::ServerEnrollmentGate(true);
	auto firstEvents = 0;
	auto secondEvents = 0;
	auto firstLifetime = rpl::lifetime();
	auto secondLifetime = rpl::lifetime();
	first.resumed() | rpl::on_next([&] { ++firstEvents; }, firstLifetime);
	second.resumed() | rpl::on_next([&] { ++secondEvents; }, secondLifetime);
	first.resumeIf(true, [&] { CHECK(first.start()); }, [] {});
	CHECK_EQ(firstEvents, 1);
	CHECK_EQ(secondEvents, 0);
	firstLifetime.destroy();
	CHECK(first.pause());
	first.resumeIf(true, [] {}, [] {});
	CHECK_EQ(firstEvents, 1);
	second.resumeIf(true, [&] { CHECK(second.start()); }, [] {});
	CHECK_EQ(secondEvents, 1);
}

TEST_CASE(EnrollmentAdmissionResumesWithFreshSerializedState) {
	using Request = MTP::details::SerializedRequest;
	using Type = Api::details::UpdateRequestState::Type;
	auto gate = MTP::ServerEnrollmentGate(true);
	auto requests = Api::details::UpdateRequestState();
	auto refusals = MTP::ServerEnrollmentRefusalQueue();
	auto blocked = MTP::DcOptions(MTP::Environment::Production);
	blocked.constructBlocked();
	auto unenrolled = MTP::DcOptions(MTP::Environment::Production);
	unenrolled.constructUnenrolled();
	auto enrolled = MTP::DcOptions(MTP::Environment::Production);
	enrolled.constructFromBuiltIn();

	auto sent = std::vector<std::pair<mtpRequestId, Request>>();
	auto failures = 0;
	auto pending = true;
	requests.started(Type::State, 41);
	auto callbacks = MTP::ResponseHandler{
		nullptr,
		[&](const MTP::Error &error, const MTP::Response &response) {
			CHECK(QThread::currentThread()
				== QCoreApplication::instance()->thread());
			CHECK(MTP::IsServerEnrollmentPausedError(error));
			CHECK_EQ(response.requestId, mtpRequestId(41));
			pending = false;
			++failures;
			CHECK(requests.finish(Type::State, response.requestId, [] {}));
			return true;
		},
	};
	auto refused = Request::Serialize(MTPupdates_GetState());
	const auto retainedRefused = refused;
	const auto refusedIdentity = retainedRefused.operator->();
	CHECK(!MTP::AdmitServerEnrollmentRequest(
		gate.networkAllowed(),
		41,
		std::move(refused),
		std::move(callbacks),
		refusals,
		[&](mtpRequestId id, Request &&request, MTP::ResponseHandler &&) {
			sent.emplace_back(id, std::move(request));
		}));
	CHECK(sent.empty());
	CHECK(pending);
	CHECK_EQ(failures, 0);
	QCoreApplication::processEvents();
	CHECK(!pending);
	CHECK_EQ(failures, 1);

	auto resumedEvents = 0;
	auto lifetime = rpl::lifetime();
	gate.resumed() | rpl::on_next([&] {
		++resumedEvents;
		requests.resumeIf(
			gate.networkAllowed(),
			[](mtpRequestId) { return false; },
			[&] {
				auto fresh = Request::Serialize(MTPupdates_GetState());
				CHECK(MTP::AdmitServerEnrollmentRequest(
						gate.networkAllowed(),
						42,
						std::move(fresh),
						MTP::ResponseHandler(),
						refusals,
						[&](mtpRequestId id, Request &&request, MTP::ResponseHandler &&) {
							sent.emplace_back(id, std::move(request));
						}));
				requests.started(Type::State, 42);
			});
	}, lifetime);
	auto start = [&] { CHECK(gate.start()); };
	gate.resumeIf(MTP::CanResumeServerEnrollment(blocked), start, [] {});
	gate.resumeIf(MTP::CanResumeServerEnrollment(unenrolled), start, [] {});
	CHECK_EQ(resumedEvents, 0);
	CHECK(sent.empty());
	gate.resumeIf(MTP::CanResumeServerEnrollment(enrolled), start, [] {});
	CHECK_EQ(resumedEvents, 1);
	CHECK(gate.networkAllowed());
	CHECK_EQ(int(sent.size()), 1);
	CHECK_EQ(sent.front().first, mtpRequestId(42));
	CHECK(sent.front().second.operator->() != refusedIdentity);
	CHECK(requests.pending());
	CHECK(requests.finishState(
		42,
		[] {},
		[&] {
			auto difference = Request::Serialize(MTPupdates_GetDifference(
				MTP_flags(0),
				MTP_int(7),
				MTPint(),
				MTPint(),
				MTP_int(1),
				MTP_int(0),
				MTPint()));
			CHECK(MTP::AdmitServerEnrollmentRequest(
				gate.networkAllowed(),
				43,
				std::move(difference),
				MTP::ResponseHandler(),
				refusals,
				[&](mtpRequestId id, Request &&request, MTP::ResponseHandler &&) {
					sent.emplace_back(id, std::move(request));
				}));
			requests.started(Type::Difference, 43);
		}));
	CHECK_EQ(int(sent.size()), 2);
	CHECK_EQ(sent.back().first, mtpRequestId(43));
	CHECK(!requests.finishState(42, [] {}, [] {}));
	gate.resumeIf(MTP::CanResumeServerEnrollment(enrolled), start, [] {});
	CHECK_EQ(resumedEvents, 1);
	CHECK_EQ(int(sent.size()), 2);
	CHECK_EQ(failures, 1);
}

TEST_CASE(RepausedGateRefusesFreshRecoveryRequest) {
	using Request = MTP::details::SerializedRequest;
	using Type = Api::details::UpdateRequestState::Type;
	auto gate = MTP::ServerEnrollmentGate();
	CHECK(gate.start());
	CHECK(gate.pause());
	auto requests = Api::details::UpdateRequestState();
	auto refusals = MTP::ServerEnrollmentRefusalQueue();
	auto sent = 0;
	auto failures = 0;
	auto lifetime = rpl::lifetime();
	gate.resumed() | rpl::on_next([&] {
		requests.resumeIf(
			gate.networkAllowed(),
			[](mtpRequestId) { return false; },
			[&] {
				CHECK(gate.pause());
				auto request = Request::Serialize(MTPupdates_GetState());
				auto callbacks = MTP::ResponseHandler{
					nullptr,
					[&](const MTP::Error &error, const MTP::Response &response) {
						CHECK(MTP::IsServerEnrollmentPausedError(error));
						CHECK(requests.finish(Type::State, response.requestId, [] {}));
						++failures;
						return true;
					},
				};
				CHECK(!MTP::AdmitServerEnrollmentRequest(
					gate.networkAllowed(),
					55,
					std::move(request),
					std::move(callbacks),
					refusals,
					[&](mtpRequestId, Request &&, MTP::ResponseHandler &&) {
						++sent;
					}));
				requests.started(Type::State, 55);
			});
	}, lifetime);
	gate.resumeIf(true, [] {}, [] {});
	CHECK_EQ(sent, 0);
	CHECK_EQ(failures, 0);
	QCoreApplication::processEvents();
	CHECK_EQ(failures, 1);
	CHECK(!requests.pending());
}
