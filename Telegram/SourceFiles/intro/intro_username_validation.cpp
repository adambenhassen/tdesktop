/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_username_validation.h"

#include "base/basic_types.h"
#include "base/qt/qt_string_view.h" // base::StringViewMid

#include <QtCore/QRegularExpression>

namespace Intro {
namespace details {

QString NormalizeUsernameInput(const QString &input) {
	auto result = input.trimmed();
	if (result.startsWith('@')) {
		result.remove(0, 1);
	}
	return result;
}

QString ToWireUsername(const QString &normalized) {
	return normalized.toLower();
}

bool IsValidUsername(const QString &normalized) {
	static const auto Pattern = QRegularExpression(
		u"^[a-zA-Z][a-zA-Z0-9_]{4,31}$"_q);
	return Pattern.match(normalized).hasMatch();
}

int FloodWaitSeconds(const QString &errorType) {
	auto from = errorType.size();
	while (from > 0 && errorType[from - 1].isDigit()) {
		--from;
	}
	return base::StringViewMid(errorType, from).toInt();
}

} // namespace details
} // namespace Intro
