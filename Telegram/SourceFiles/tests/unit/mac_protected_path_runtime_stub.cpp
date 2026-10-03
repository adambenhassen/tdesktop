/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/mac_protected_path_runtime.h"

namespace Core::MacProtectedPath {

bool CheckPath(Operation, const QString &, const char *) { return true; }

bool CheckExternalPath(Operation, const QString &, const char *) {
	return true;
}

bool CheckPair(Operation, const QString &, const QString &, const char *) {
	return true;
}

} // namespace Core::MacProtectedPath
