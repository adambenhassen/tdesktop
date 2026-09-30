/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "core/mac_protected_path_policy.h"

namespace Core::MacProtectedPath {

#ifdef Q_OS_MAC
[[nodiscard]] bool InitializeProfile();
[[nodiscard]] bool IntegrationTestActive();
[[nodiscard]] QString IpcDirectory();
[[nodiscard]] QString NotificationSoundsDirectory();
[[nodiscard]] QString ProfileRoot();

[[nodiscard]] bool CheckPath(Operation operation, const QString &path,
							 const char *callsite);

[[nodiscard]] bool CheckPair(Operation operation, const QString &first,
							 const QString &second, const char *callsite);
#else  // Q_OS_MAC
[[nodiscard]] inline bool InitializeProfile() { return true; }
[[nodiscard]] inline bool IntegrationTestActive() { return false; }
[[nodiscard]] inline QString IpcDirectory() { return {}; }
[[nodiscard]] inline QString NotificationSoundsDirectory() { return {}; }
[[nodiscard]] inline QString ProfileRoot() { return {}; }
[[nodiscard]] inline bool CheckPath(Operation, const QString &, const char *) {
	return true;
}
[[nodiscard]] inline bool CheckPair(Operation, const QString &, const QString &,
									const char *) {
	return true;
}
#endif // !Q_OS_MAC

} // namespace Core::MacProtectedPath
