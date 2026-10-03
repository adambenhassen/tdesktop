/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <string_view>

namespace Core {

enum class TeagramIconChoice {
	Mug,
	T,
};

inline constexpr auto kTeagramIconChoicePreference
	= std::string_view("teagram-icon-is-t");

template <typename Settings>
[[nodiscard]] TeagramIconChoice ReadTeagramIconChoice(Settings &settings) {
	return settings.template readPref<bool>(kTeagramIconChoicePreference)
		? TeagramIconChoice::T
		: TeagramIconChoice::Mug;
}

template <typename Settings>
void WriteTeagramIconChoice(
		Settings &settings,
		TeagramIconChoice choice) {
	settings.template writePref<bool>(
		kTeagramIconChoicePreference,
		choice == TeagramIconChoice::T);
}

} // namespace Core
