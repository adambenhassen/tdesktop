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

QString AstralString(int count) {
	return QString::fromUtf8("\xF0\x9F\x98\x80").repeated(count);
}

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

const auto kServerA = UsernameServerIdentity{ u"10.0.0.1"_q, 443, 111 };
const auto kServerB = UsernameServerIdentity{ u"10.0.0.2"_q, 443, 222 };

TEST_CASE(CacheIsFreshOnlyForSameNameInsideWindow) {
	const auto name = u"alice"_q;
	const auto cache = UsernameCodeCache{
		name,
		kServerA,
		QByteArray("hash"),
		1000,
	};

	CHECK(cache.freshFor(name, kServerA, 1000));
	// The window is four minutes: checked as literals so a change to
	// kFreshForMs cannot move the goalposts of its own test.
	constexpr auto kFourMinutesMs = qint64(4) * 60 * 1000;
	CHECK(cache.freshFor(name, kServerA, 1000 + kFourMinutesMs - 1));
	// codeTTL on the server is 5 minutes; the cache holds only 4, so a
	// hash that is still valid on the wire is not reused past the window.
	CHECK(!cache.freshFor(name, kServerA, 1000 + kFourMinutesMs));

	// Another username reissues.
	CHECK(!cache.freshFor(u"bob"_q, kServerA, 1001));
}

TEST_CASE(CacheNeverCrossesToAnotherServer) {
	const auto name = u"alice"_q;
	const auto cache = UsernameCodeCache{
		name,
		kServerA,
		QByteArray("hash"),
		1000,
	};

	// Back to the server step, commit a different pair, submit the same
	// name inside the window: server A's hash must not reach server B.
	CHECK(!cache.freshFor(name, kServerB, 1001));
	// One differing component of the triple is enough.
	CHECK(!cache.freshFor(
		name,
		UsernameServerIdentity{ u"10.0.0.1"_q, 443, 999 },
		1001));
	CHECK(!cache.freshFor(
		name,
		UsernameServerIdentity{ u"10.0.0.1"_q, 8443, 111 },
		1001));
	CHECK(!cache.freshFor(
		name,
		UsernameServerIdentity{ u"10.0.0.9"_q, 443, 111 },
		1001));

	// Fails closed when either side has no usable server identity.
	CHECK(!cache.freshFor(name, UsernameServerIdentity(), 1001));
	const auto noServer = UsernameCodeCache{
		name,
		UsernameServerIdentity(),
		QByteArray("hash"),
		1000,
	};
	CHECK(!noServer.freshFor(name, kServerA, 1001));
}

TEST_CASE(ServerIdentityIsEmptyWithoutAllThreeParts) {
	CHECK(!kServerA.empty());
	CHECK(UsernameServerIdentity().empty());
	const auto noIp = UsernameServerIdentity{ QString(), 443, 111 };
	const auto noPort = UsernameServerIdentity{ u"10.0.0.1"_q, 0, 111 };
	// No pinned key fingerprint is no identity at all.
	const auto noKey = UsernameServerIdentity{ u"10.0.0.1"_q, 443, 0 };
	CHECK(noIp.empty());
	CHECK(noPort.empty());
	CHECK(noKey.empty());
}

TEST_CASE(DroppedAndEmptyCachesNeverLookFresh) {
	auto cache = UsernameCodeCache{
		u"alice"_q,
		kServerA,
		QByteArray("hash"),
		1000,
	};
	cache.drop();
	CHECK(cache.hash.isEmpty());
	CHECK(!cache.freshFor(u"alice"_q, kServerA, 1000));

	const auto neverIssued = UsernameCodeCache();
	CHECK(!neverIssued.freshFor(u"alice"_q, kServerA, 1000));
}

TEST_CASE(FloodWaitSecondsReadsDigitsFromTheEnd) {
	CHECK_EQ(FloodWaitSeconds(u"FLOOD_WAIT_42"_q), 42);
	// The whole family, not just the fixed FLOOD_WAIT_ prefix length:
	// MTP::IsFloodError matches this one too and a fixed offset read 0.
	CHECK_EQ(FloodWaitSeconds(u"FLOOD_PREMIUM_WAIT_42"_q), 42);
	CHECK_EQ(FloodWaitSeconds(u"FLOOD_WAIT_0"_q), 0);
	CHECK_EQ(FloodWaitSeconds(u"FLOOD_WAIT_3600"_q), 3600);
	// No trailing digits at all degrades to 0 rather than misreading.
	CHECK_EQ(FloodWaitSeconds(u"FLOOD_WAIT_"_q), 0);
	CHECK_EQ(FloodWaitSeconds(QString()), 0);
}

TEST_CASE(SignupNameValidationTrimsAndCapsInput) {
	CHECK(
		ValidateSignupName(u"  Ada Lovelace  "_q)
		== SignupNameValidation::Valid);
	CHECK(
		ValidateSignupName(QString(60, QChar('x')))
		== SignupNameValidation::Valid);
	CHECK(
		ValidateSignupName(QString(61, QChar('x')))
		== SignupNameValidation::TooLong);
	CHECK(
		ValidateSignupName(u" \t\n"_q)
		== SignupNameValidation::Empty);
}

TEST_CASE(SignupNameValidationDoesNotImposeCompositionRules) {
	CHECK(
		ValidateSignupName(u"  你好\u200f  "_q)
		== SignupNameValidation::Valid);
}

TEST_CASE(SignupNameValidationCountsUnicodeScalars) {
	CHECK(
		ValidateSignupName(AstralString(60))
		== SignupNameValidation::Valid);
	CHECK(
		ValidateSignupName(AstralString(61))
		== SignupNameValidation::TooLong);
}

TEST_CASE(SignupPasswordValidationReportsTheFirstFix) {
	CHECK(
		ValidateSignupPassword(QString(), QString())
		== SignupPasswordValidation::Empty);
	CHECK(
		ValidateSignupPassword(u"short"_q, u"short"_q)
		== SignupPasswordValidation::TooShort);
	CHECK(
		ValidateSignupPassword(u"long enough"_q, QString())
		== SignupPasswordValidation::RepeatEmpty);
	CHECK(
		ValidateSignupPassword(u"long enough"_q, u"different"_q)
		== SignupPasswordValidation::Mismatch);
	CHECK(
		ValidateSignupPassword(u"long enough"_q, u"long enough"_q)
		== SignupPasswordValidation::Valid);
}

TEST_CASE(SignupPasswordValidationCountsUnicodeScalars) {
	CHECK(
		ValidateSignupPassword(AstralString(7), AstralString(7))
		== SignupPasswordValidation::TooShort);
	CHECK(
		ValidateSignupPassword(AstralString(8), AstralString(8))
		== SignupPasswordValidation::Valid);
}

TEST_CASE(SignupPasswordUpdateKeepsFloodVisible) {
	CHECK(
		ClassifySignupPasswordUpdateFailure(u"FLOOD_WAIT_60"_q)
		== SignupPasswordUpdateFailure::Flood);
	CHECK(
		ClassifySignupPasswordUpdateFailure(u"FLOOD_PREMIUM_WAIT_60"_q)
		== SignupPasswordUpdateFailure::Flood);
	CHECK(
		ClassifySignupPasswordUpdateFailure(u"NEW_PASSWORD_BAD"_q)
		== SignupPasswordUpdateFailure::InvalidVerifier);
	CHECK(
		ClassifySignupPasswordUpdateFailure(u"NEW_SALT_INVALID"_q)
		== SignupPasswordUpdateFailure::InvalidVerifier);
	CHECK(
		ClassifySignupPasswordUpdateFailure(u"INTERNAL"_q)
		== SignupPasswordUpdateFailure::Other);
}

TEST_CASE(SigninPasswordValidationRejectsEmptyInput) {
	CHECK(
		ValidateSigninPassword(QString())
		== SigninPasswordValidation::Empty);
	CHECK(
		ValidateSigninPassword(u"correct horse battery staple"_q)
		== SigninPasswordValidation::Valid);
}

TEST_CASE(SigninPasswordFailuresHaveExplicitFallbacks) {
	CHECK(
		ClassifySigninPasswordFailure(u"PASSWORD_HASH_INVALID"_q)
		== SigninPasswordFailure::WrongPassword);
	CHECK(
		ClassifySigninPasswordFailure(u"FLOOD_WAIT_60"_q)
		== SigninPasswordFailure::Flood);
	CHECK(
		ClassifySigninPasswordFailure(u"SRP_ID_INVALID"_q)
		== SigninPasswordFailure::SrpIdInvalid);
	CHECK(
		ClassifySigninPasswordFailure(u"UNEXPECTED_ERROR"_q)
		== SigninPasswordFailure::Other);
}

} // namespace
