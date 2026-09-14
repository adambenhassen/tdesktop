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
} // namespace Storage

namespace Main::details {

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
