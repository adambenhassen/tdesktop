/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

namespace Data::details {

[[nodiscard]] constexpr bool CanMarkUserLoadedNormally(
		bool isSelf,
		bool hasPhone,
		bool hasCustomServer) {
	return !isSelf || hasPhone || hasCustomServer;
}

} // namespace Data::details
