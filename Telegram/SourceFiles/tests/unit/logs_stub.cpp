/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/

// td_mtproto reaches for the application's log files through MTP_LOG,
// whose definitions live in the application target. The unit tests link
// the library without the application, so the three symbols that macro
// needs are defined here as no-ops that discard the line.

#include "logs.h"

namespace Logs {

bool DebugEnabled() {
	return false;
}

bool started() {
	return false;
}

void writeMtp(int32 dc, const QString &v) {
}

} // namespace Logs
