/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

namespace Storage {
class Account;
struct ServerCacheBinding;
} // namespace Storage

namespace Main::details {

enum class ServerReenrollmentPrompt {
	IdentityChange,
	DestructiveConfirmation,
};

// Only an affirmative action on the final confirmation may reach the
// destructive re-enrollment callback. The first prompt is informational,
// so accepting it only advances to that final boundary.
[[nodiscard]] bool CommitServerReenrollment(
	ServerReenrollmentPrompt prompt,
	bool accepted,
	Fn<bool()> commit);

[[nodiscard]] bool ShouldBlockRestoredSessionWithoutServerPin(
	bool hasRestoredUserId,
	bool hasReadableServerPin);

[[nodiscard]] bool CommitServerForget(
	not_null<Storage::Account*> local,
	Storage::ServerCacheBinding binding,
	Fn<void()> restart);

// Keep the durable authorization boundary identical for the two real
// Main::Account lifecycle callers. The storage object is the mandatory seam,
// so tests cannot bypass the production write path with a synthetic writer.
[[nodiscard]] bool CommitPostAuthMtpAuthorization(
	not_null<Storage::Account*> local,
	Fn<void()> committed,
	Fn<void()> failed);

[[nodiscard]] bool CommitTeardownMtpAuthorization(
	not_null<Storage::Account*> local,
	Fn<void()> committed,
	Fn<void()> failed);

} // namespace Main::details
