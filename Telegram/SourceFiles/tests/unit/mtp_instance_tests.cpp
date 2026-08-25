/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "mtproto/mtp_instance.h"

namespace {

using namespace MTP;

[[nodiscard]] PinnedServerFailureReport Report(
		ShiftedDcId shiftedDcId,
		PinnedServerFailure failure) {
	return { shiftedDcId, failure };
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
