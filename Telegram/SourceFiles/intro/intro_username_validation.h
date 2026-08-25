/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace Intro {
namespace details {

enum class SignupNameValidation {
	Valid,
	Empty,
	TooLong,
};

enum class SignupPasswordValidation {
	Valid,
	Empty,
	TooShort,
	RepeatEmpty,
	Mismatch,
};

enum class SignupPasswordUpdateFailure {
	Flood,
	InvalidVerifier,
	Other,
};

// Forgiving normalisation of what the user typed: trim surrounding
// whitespace and strip a single leading '@' (people type "@alice").
// Neither is a keystroke filter — the field accepts anything and this
// runs in submit(), where a broken rule can be stated in full.
[[nodiscard]] QString NormalizeUsernameInput(const QString &input);

// The form that goes on the wire. The server lowercases usernames
// anyway; lowercasing here keeps the hash cache keyed consistently.
// What the user typed stays on screen.
[[nodiscard]] QString ToWireUsername(const QString &normalized);

// The server's own username pattern: 5 to 32 characters, ASCII letters,
// digits and underscore, starting with a letter. Checked before any
// network call — sendCode is limited to 10 per hour per IP.
[[nodiscard]] bool IsValidUsername(const QString &normalized);

// Which server a phone_code_hash came from: address, port and the
// fingerprint of the pinned key, the same triple the same-account
// shortcut compares. A hash is a ticket one server minted, so it must
// never travel to another one — the user can walk Back to the server
// step and commit a different pair inside the freshness window.
struct UsernameServerIdentity {
	QString ip;
	int port = 0;
	uint64 keyFingerprint = 0;

	// No committed server, or one without a pinned key, is not an
	// identity anything may be matched against.
	[[nodiscard]] bool empty() const {
		return ip.isEmpty() || !port || !keyFingerprint;
	}

	friend inline bool operator==(
		const UsernameServerIdentity &,
		const UsernameServerIdentity &) = default;
};

// A phone_code_hash issued by auth.sendCode, kept so a back-and-forward
// loop does not burn another shared per-IP sendCode call. codeTTL on
// the server is 5 minutes; the cache holds for 4, leaving a minute of
// slack between re-issuing and signing in with what was issued.
struct UsernameCodeCache {
	QString username;
	UsernameServerIdentity server;
	QByteArray hash;
	qint64 issuedAt = 0;

	static constexpr auto kFreshForMs = qint64(4) * 60 * 1000;

	// Fails closed: an unknown server on either side is never a match.
	[[nodiscard]] bool freshFor(
			const QString &wireUsername,
			const UsernameServerIdentity &currentServer,
			qint64 now) const {
		return !hash.isEmpty()
			&& username == wireUsername
			&& !server.empty()
			&& !currentServer.empty()
			&& server == currentServer
			&& now >= issuedAt
			&& (now - issuedAt) < kFreshForMs;
	}
	void drop() {
		*this = UsernameCodeCache();
	}
};

// The number of seconds out of a FLOOD_WAIT_<n> error type. The family
// is open-ended — MTP::IsFloodError also matches FLOOD_PREMIUM_WAIT_<n>
// — so the digits come off the end rather than a fixed prefix length.
// A type with no trailing digits yields 0.
[[nodiscard]] int FloodWaitSeconds(const QString &errorType);

[[nodiscard]] SignupNameValidation ValidateSignupName(
	const QString &input);
[[nodiscard]] QString NormalizeSignupNameInput(const QString &input);

[[nodiscard]] SignupPasswordValidation ValidateSignupPassword(
	const QString &password,
	const QString &repeat);

[[nodiscard]] SignupPasswordUpdateFailure
ClassifySignupPasswordUpdateFailure(const QString &errorType);

} // namespace details
} // namespace Intro
