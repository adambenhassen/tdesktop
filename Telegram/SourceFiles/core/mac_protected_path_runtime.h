/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "core/mac_protected_path_policy.h"

#include <functional>

namespace Core::MacProtectedPath {

#ifdef Q_OS_MAC
[[nodiscard]] bool InitializeProfile();
[[nodiscard]] bool IntegrationTestActive();
[[nodiscard]] QString InitialWorkingDirectory();
[[nodiscard]] QString IpcDirectory();
[[nodiscard]] QString NotificationSoundsDirectory();
[[nodiscard]] QString ProfileRoot();

[[nodiscard]] bool CheckPath(Operation operation, const QString &path,
							 const char *callsite);

[[nodiscard]] bool CheckPathAt(Operation operation, const QString &path,
							   const QString &anchor, const char *callsite);

[[nodiscard]] bool CheckExternalPath(Operation operation, const QString &path,
									 const char *callsite);

[[nodiscard]] bool CheckCachePath(const QString &path, const char *callsite);

#if defined(TDESKTOP_MAC_PROTECTED_PATH_INTEGRATION_TEST)
[[nodiscard]] bool
CheckCachePathForTesting(const QString &path, const char *callsite,
						 std::function<void(const QString &)> beforeEntryStat);
#endif

[[nodiscard]] bool CheckPair(Operation operation, const QString &first,
							 const QString &second, const char *callsite);
#else  // Q_OS_MAC
[[nodiscard]] inline bool InitializeProfile() { return true; }
[[nodiscard]] inline bool IntegrationTestActive() { return false; }
[[nodiscard]] inline QString InitialWorkingDirectory() { return {}; }
[[nodiscard]] inline QString IpcDirectory() { return {}; }
[[nodiscard]] inline QString NotificationSoundsDirectory() { return {}; }
[[nodiscard]] inline QString ProfileRoot() { return {}; }
[[nodiscard]] inline bool CheckPath(Operation, const QString &, const char *) {
	return true;
}
[[nodiscard]] inline bool CheckPathAt(Operation, const QString &,
									  const QString &, const char *) {
	return true;
}
[[nodiscard]] inline bool CheckExternalPath(Operation, const QString &,
											const char *) {
	return true;
}
[[nodiscard]] inline bool CheckCachePath(const QString &, const char *) {
	return true;
}
[[nodiscard]] inline bool CheckPair(Operation, const QString &, const QString &,
									const char *) {
	return true;
}
#endif // !Q_OS_MAC

} // namespace Core::MacProtectedPath
