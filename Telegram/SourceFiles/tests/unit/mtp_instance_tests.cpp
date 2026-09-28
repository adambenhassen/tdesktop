/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/mtproto_dc_options.h"

#include <utility>

namespace {

using namespace MTP;

const char kPinnedServerKey[] = "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n\
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n\
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n\
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n\
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n\
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n\
-----END RSA PUBLIC KEY-----";

[[nodiscard]] std::shared_ptr<details::RSAPublicKey> MakePinnedServerKey() {
	return std::make_shared<details::RSAPublicKey>(bytes::make_span(
		kPinnedServerKey,
		sizeof(kPinnedServerKey) - 1));
}

[[nodiscard]] PinnedServerFailureReport Report(
		ShiftedDcId shiftedDcId,
		PinnedServerFailure failure,
		uint64 pinnedFingerprint = 0,
		uint64 presentedFingerprint = 0,
		QString pinnedHostname = {},
		QString dialledAddress = {}) {
	return {
		shiftedDcId,
		failure,
		pinnedFingerprint,
		presentedFingerprint,
		std::move(pinnedHostname),
		std::move(dialledAddress),
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

TEST_CASE(KeyMismatchReportPreservesPinAndEndpointIdentity) {
	const auto key = MakePinnedServerKey();
	const auto pinned = CustomServer{
		.dcId = 2,
		.hostname = "telegram-server.tailaa4918.ts.net",
		.port = 2443,
		.key = key,
		.serverSelection = "telegram-server.tailaa4918.ts.net",
		.discoveryPolicy = ServerDiscoveryPolicy::PublicHttps,
		.discoveryOrigin =
			"https://telegram-server.tailaa4918.ts.net/"
			".well-known/telegramd/client",
	};
	const auto before = pinned;
	const auto report = MakePinnedServerFailureReport(
		2,
		PinnedServerFailure::KeyMismatch,
		456,
		pinned,
		u"telegram-server.tailaa4918.ts.net"_q,
		u"100.124.236.66"_q);

	PinnedServerFailureChannel channel;
	channel.report(report);
	CHECK(channel.current().has_value());
	if (channel.current()) {
		CHECK_EQ(
			channel.current()->pinnedFingerprint,
			uint64(key->fingerprint()));
		CHECK_EQ(channel.current()->presentedFingerprint, uint64(456));
		CHECK_EQ(
			channel.current()->pinnedHostname,
			u"telegram-server.tailaa4918.ts.net"_q);
		CHECK_EQ(
			channel.current()->dialledAddress,
			u"100.124.236.66"_q);
	}
	CHECK(SameCustomServerPin(pinned, before));
}

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

TEST_CASE(PinnedServerFailureKeepsEndpointIdentity) {
	const auto report = Report(
		2,
		PinnedServerFailure::KeyMismatch,
		123,
		456,
		u"server.example.com"_q,
		u"100.124.236.66"_q);
	PinnedServerFailureChannel channel;
	channel.report(report);

	CHECK(channel.current().has_value());
	CHECK_EQ(channel.current()->pinnedHostname, u"server.example.com"_q);
	CHECK_EQ(channel.current()->dialledAddress, u"100.124.236.66"_q);
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
