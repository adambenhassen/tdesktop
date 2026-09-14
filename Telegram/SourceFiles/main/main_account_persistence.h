/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

namespace Main::details {

// Keep the durable authorization boundary identical for post-auth startup
// and account teardown. The caller owns the state transition on either side
// of the write, so a failed commit cannot publish or discard that state.
[[nodiscard]] inline bool CommitMtpAuthorization(
	Fn<bool()> write,
	Fn<void()> committed,
	Fn<void()> failed) {
	if (!write()) {
		failed();
		return false;
	}
	committed();
	return true;
}

} // namespace Main::details
