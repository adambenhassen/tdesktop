/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QString>

namespace Core {

enum class UpdateEntryPoint {
	Automatic,
	Periodic,
	Settings,
	CrashWindowRetry,
	CrashWindowGetApp,
	Manual,
};

// The client is enrolled against an operator-selected server and has no
// trusted update origin. Keep this policy pure so every entry point can be
// tested without starting the application or a network stack.
[[nodiscard]] constexpr bool UpdateNetworkAllowed(UpdateEntryPoint) {
	return false;
}

[[nodiscard]] inline bool AcceptServerAutoupdatePrefix(
	const QString &) {
	return false;
}

} // namespace Core
