/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

namespace Storage::details {

enum class ServerForgetStartupResult {
	Loaded,
	Forgotten,
	Blocked,
};

[[nodiscard]] ServerForgetStartupResult ProcessServerForgetStartup(
	bool serverForgetPending,
	Fn<void(bool)> readMapWith,
	Fn<void()> clearLegacyFiles,
	Fn<bool()> completeServerForget,
	Fn<void()> readStoredCustomServerPin,
	Fn<void()> readMtpConfig);

} // namespace Storage::details
