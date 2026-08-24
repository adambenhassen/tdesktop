/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "intro/intro_username_validation.h"

namespace {

using namespace Intro::details;

TEST_CASE(NormalizeTrimsWhitespace) {
	CHECK_EQ(NormalizeUsernameInput(u"  alice  "_q), u"alice"_q);
	CHECK_EQ(NormalizeUsernameInput(u"\talice\n"_q), u"alice"_q);
}

TEST_CASE(NormalizeStripsOneLeadingAt) {
	CHECK_EQ(NormalizeUsernameInput(u"@alice"_q), u"alice"_q);
	// A second '@' survives normalisation and fails the pattern later:
	// it is a typo, not something to silently swallow.
	CHECK_EQ(NormalizeUsernameInput(u"@@alice"_q), u"@alice"_q);
	CHECK_EQ(NormalizeUsernameInput(u"alice"_q), u"alice"_q);
}

TEST_CASE(ValidUsernamesAtBoundaries) {
	CHECK(IsValidUsername(u"abcde"_q)); // 5 chars, the shortest.
	CHECK(IsValidUsername(
		u"abcdefghijklmnopqrstuvwxyz012345"_q)); // 32 chars, the longest.
	CHECK(!IsValidUsername(u"abcd"_q)); // 4 chars, one too short.
	CHECK(!IsValidUsername(
		u"abcdefghijklmnopqrstuvwxyz0123456"_q)); // 33 chars.
}

TEST_CASE(UsernamesRejectedByPattern) {
	CHECK(!IsValidUsername(u"1alice"_q)); // Must start with a letter.
	CHECK(!IsValidUsername(u"_alice"_q));
	CHECK(!IsValidUsername(u"al-ice"_q)); // Dash outside the class.
	CHECK(!IsValidUsername(u"al ice"_q)); // Inner space is not trimmed away.
	CHECK(!IsValidUsername(u"alice!"_q));
	CHECK(!IsValidUsername(QString())); // Empty is its own message.
	CHECK(!IsValidUsername(u"ali\u0441e"_q)); // Non-ASCII inside.
}

TEST_CASE(WireFormIsLowercased) {
	CHECK_EQ(ToWireUsername(u"Alice"_q), u"alice"_q);
	CHECK_EQ(ToWireUsername(u"Alice_1B"_q), u"alice_1b"_q);
}

TEST_CASE(CacheIsFreshOnlyForSameNameInsideWindow) {
	const auto name = u"alice"_q;
	const auto cache = UsernameCodeCache{
		name,
		QByteArray("hash"),
		1000,
	};

	CHECK(cache.freshFor(name, 1000));
	// The window is four minutes: checked as literals so a change to
	// kFreshForMs cannot move the goalposts of its own test.
	constexpr auto kFourMinutesMs = qint64(4) * 60 * 1000;
	CHECK(cache.freshFor(name, 1000 + kFourMinutesMs - 1));
	// codeTTL on the server is 5 minutes; the cache holds only 4, so a
	// hash that is still valid on the wire is not reused past the window.
	CHECK(!cache.freshFor(name, 1000 + kFourMinutesMs));

	CHECK(!cache.freshFor(u"bob"_q, 1001)); // Another username reissues.
}

TEST_CASE(DroppedAndEmptyCachesNeverLookFresh) {
	auto cache = UsernameCodeCache{ u"alice"_q, QByteArray("hash"), 1000 };
	cache.drop();
	CHECK(cache.hash.isEmpty());
	CHECK(!cache.freshFor(u"alice"_q, 1000));

	const auto neverIssued = UsernameCodeCache();
	CHECK(!neverIssued.freshFor(u"alice"_q, 1000));
}

} // namespace
