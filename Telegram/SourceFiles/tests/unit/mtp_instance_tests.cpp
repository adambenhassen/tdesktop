/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "api/api_updates.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/mtproto_dc_options.h"

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

TEST_CASE(EnrollmentRecoveryUsesFreshAccountScopedRequests) {
	using Type = Api::details::UpdateRequestState::Type;
	auto accountA = Api::details::UpdateRequestState();
	auto accountB = Api::details::UpdateRequestState();
	auto sent = std::vector<mtpRequestId>();
	auto stored = std::vector<mtpRequestId>();
	auto applied = 0;
	auto differenceApplied = 0;
	auto failures = 0;
	auto gate = MTP::ServerEnrollmentGate(true);
	auto initialFailure = MTP::ResponseHandler{
		nullptr,
		[&](const MTP::Error &error, const MTP::Response &response) {
			++failures;
			CHECK(MTP::IsServerEnrollmentPausedError(error));
			CHECK_EQ(response.requestId, mtpRequestId(41));
			CHECK(accountA.finish(
				Type::State,
				response.requestId,
				[] {}));
			return true;
		}
	};
	auto queuedFailure = Fn<void()>();

	accountA.started(Type::State, 41);
	CHECK(accountA.pending());
	const auto refused = MTP::RejectServerEnrollmentRequest(
		gate.networkAllowed(),
		mtpRequestId(41),
		initialFailure,
		[&](Fn<void()> callback) {
			queuedFailure = std::move(callback);
		});
	CHECK(refused);
	if (!refused) {
		stored.push_back(mtpRequestId(41));
	}
	CHECK(queuedFailure);
	CHECK_EQ(int(stored.size()), 0);
	CHECK_EQ(failures, 0);
	queuedFailure();
	queuedFailure = nullptr;
	CHECK_EQ(failures, 1);
	CHECK(!accountA.pending());
	CHECK(gate.resume().resumed);
	CHECK(!gate.networkAllowed());
	CHECK(!accountA.canStart(
		gate.networkAllowed(),
		[](mtpRequestId) { return false; }));
	CHECK(sent.empty());

	CHECK(gate.start());
	auto allowedCallbacks = MTP::ResponseHandler{
		nullptr,
		[](const MTP::Error &, const MTP::Response &) {
			return true;
		}
	};
	auto scheduledAllowedFailure = false;
	CHECK(!MTP::RejectServerEnrollmentRequest(
		gate.networkAllowed(),
		mtpRequestId(44),
		allowedCallbacks,
		[&](Fn<void()>) {
			scheduledAllowedFailure = true;
		}));
	CHECK(allowedCallbacks.fail);
	CHECK(!scheduledAllowedFailure);
	auto noCallbacks = MTP::ResponseHandler();
	if (accountA.canStart(
			gate.networkAllowed(),
			[](mtpRequestId) { return false; })) {
		const auto fresh = mtpRequestId(42);
		if (!MTP::RejectServerEnrollmentRequest(
				gate.networkAllowed(),
				fresh,
				noCallbacks,
				[](Fn<void()>) {
				})) {
			sent.push_back(fresh);
			accountA.started(Type::State, fresh);
		}
	}
	CHECK_EQ(int(sent.size()), 1);
	CHECK_EQ(sent.front(), mtpRequestId(42));

	CHECK(gate.pause());
	CHECK(MTP::RejectServerEnrollmentRequest(
		gate.networkAllowed(),
		mtpRequestId(43),
		noCallbacks,
		[](Fn<void()>) {
		}));
	CHECK(!accountA.canStart(gate.networkAllowed(), [](mtpRequestId) {
		return false;
	}));
	CHECK_EQ(int(sent.size()), 1);

	CHECK(!accountA.finish(Type::State, 41, [&] { ++applied; }));
	CHECK(accountA.pending());

	accountB.started(Type::Difference, 51);
	CHECK(accountB.pending());
	CHECK(accountA.pending());

	CHECK(accountA.finish(Type::State, 42, [&] { ++applied; }));
	CHECK(!accountA.finish(Type::State, 42, [&] { ++applied; }));
	CHECK_EQ(applied, 1);
	CHECK(!accountA.pending());
	CHECK(accountB.finish(
		Type::Difference,
		51,
		[&] { ++differenceApplied; }));
	CHECK(!accountB.finish(
		Type::Difference,
		51,
		[&] { ++differenceApplied; }));
	CHECK_EQ(differenceApplied, 1);
	CHECK(!accountB.pending());
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

TEST_CASE(EnrollmentResumeRequiresAUsablePin) {
	auto blocked = MTP::DcOptions(MTP::Environment::Production);
	blocked.constructBlocked();
	auto unenrolled = MTP::DcOptions(MTP::Environment::Production);
	unenrolled.constructUnenrolled();
	auto enrolled = MTP::DcOptions(MTP::Environment::Production);
	enrolled.constructFromBuiltIn();

	auto gate = MTP::ServerEnrollmentGate(true);
	auto resumedEvents = 0;
	auto tryResume = [&](const MTP::DcOptions &options) {
		if (!MTP::CanResumeServerEnrollment(options)) {
			return;
		}
		const auto result = gate.resume();
		if (!result.resumed) {
			return;
		}
		if (!result.wasStarted) {
			gate.start();
		}
		if (gate.networkAllowed()) {
			++resumedEvents;
		}
	};

	tryResume(blocked);
	tryResume(unenrolled);
	CHECK_EQ(resumedEvents, 0);
	CHECK(!gate.networkAllowed());
	tryResume(enrolled);
	CHECK_EQ(resumedEvents, 1);
}
