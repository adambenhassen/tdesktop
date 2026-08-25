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

QString NormalizeSignupNameInput(const QString &input) {
	return input.trimmed();
}

SignupNameValidation ValidateSignupName(const QString &input) {
	const auto normalized = NormalizeSignupNameInput(input);
	if (normalized.isEmpty()) {
		return SignupNameValidation::Empty;
	} else if (normalized.size() > 60) {
		return SignupNameValidation::TooLong;
	}
	return SignupNameValidation::Valid;
}

SignupPasswordValidation ValidateSignupPassword(
		const QString &password,
		const QString &repeat) {
	if (password.isEmpty()) {
		return SignupPasswordValidation::Empty;
	} else if (password.size() < 8) {
		return SignupPasswordValidation::TooShort;
	} else if (repeat.isEmpty()) {
		return SignupPasswordValidation::RepeatEmpty;
	} else if (password != repeat) {
		return SignupPasswordValidation::Mismatch;
	}
	return SignupPasswordValidation::Valid;
}

SignupPasswordUpdateFailure ClassifySignupPasswordUpdateFailure(
		const QString &errorType) {
	if (errorType.startsWith(u"FLOOD_WAIT_"_q)
		|| errorType.startsWith(u"FLOOD_PREMIUM_WAIT_"_q)) {
		return SignupPasswordUpdateFailure::Flood;
	} else if (errorType == u"NEW_PASSWORD_BAD"_q
		|| errorType == u"NEW_SALT_INVALID"_q) {
		return SignupPasswordUpdateFailure::InvalidVerifier;
	}
	return SignupPasswordUpdateFailure::Other;
}

} // namespace details
} // namespace Intro
