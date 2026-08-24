/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace Intro {
namespace details {

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

// A phone_code_hash issued by auth.sendCode, kept so a back-and-forward
// loop does not burn another shared per-IP sendCode call. codeTTL on
// the server is 5 minutes; the cache holds for 4, leaving a minute of
// slack between re-issuing and signing in with what was issued.
struct UsernameCodeCache {
	QString username;
	QByteArray hash;
	qint64 issuedAt = 0;

	static constexpr auto kFreshForMs = qint64(4) * 60 * 1000;

	[[nodiscard]] bool freshFor(const QString &wireUsername, qint64 now) const {
		return !hash.isEmpty()
			&& username == wireUsername
			&& now >= issuedAt
			&& (now - issuedAt) < kFreshForMs;
	}
	void drop() {
		*this = UsernameCodeCache();
	}
};

} // namespace details
} // namespace Intro
