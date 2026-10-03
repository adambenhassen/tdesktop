/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <array>
#include <string_view>

namespace Core {

enum class TeagramIconChoice : int {
	MugSignal = 0,
	MugTea = 1,
	MugGreen = 2,
	MugSky = 3,
	TPrimary = 4,
	TNavy = 5,
	TNight = 6,
	TPaper = 7,
	MugCrimson = 8,
	TCrimson = 9,
	MugBrown = 10,
	TBrown = 11,
};

inline constexpr auto kTeagramIconChoicePreference
	= std::string_view("teagram-icon-choice");
inline constexpr auto kLegacyTeagramIconChoicePreference
	= std::string_view("teagram-icon-is-t");

inline constexpr auto kTeagramIconSvgResources = std::array{
	std::string_view(":/gui/art/teagram-icon.svg"),
	std::string_view(":/gui/art/teagram-app-icon-mug-tea.svg"),
	std::string_view(":/gui/art/teagram-app-icon-mug-green.svg"),
	std::string_view(":/gui/art/teagram-app-icon-mug-sky.svg"),
	std::string_view(":/gui/art/teagram-app-icon-t.svg"),
	std::string_view(":/gui/art/teagram-app-icon-t-navy.svg"),
	std::string_view(":/gui/art/teagram-app-icon-t-night.svg"),
	std::string_view(":/gui/art/teagram-app-icon-t-paper.svg"),
	std::string_view(":/gui/art/teagram-app-icon-mug-crimson.svg"),
	std::string_view(":/gui/art/teagram-app-icon-t-crimson.svg"),
	std::string_view(":/gui/art/teagram-app-icon-mug-brown.svg"),
	std::string_view(":/gui/art/teagram-app-icon-t-brown.svg"),
};
inline constexpr auto kTeagramIconChoiceCount = static_cast<int>(
	kTeagramIconSvgResources.size());

[[nodiscard]] constexpr std::string_view TeagramIconSvgResource(
		TeagramIconChoice choice) {
	const auto index = static_cast<int>(choice);
	return (index >= 0 && index < kTeagramIconChoiceCount)
		? kTeagramIconSvgResources[index]
		: kTeagramIconSvgResources[0];
}

template <typename Settings>
[[nodiscard]] TeagramIconChoice ReadTeagramIconChoice(Settings &settings) {
	const auto choice = settings.template readPref<int>(
		kTeagramIconChoicePreference,
		-1);
	if (choice >= 0 && choice < kTeagramIconChoiceCount) {
		return static_cast<TeagramIconChoice>(choice);
	}
	return settings.template readPref<bool>(
		kLegacyTeagramIconChoicePreference)
		? TeagramIconChoice::TPrimary
		: TeagramIconChoice::MugSignal;
}

template <typename Settings>
void WriteTeagramIconChoice(
		Settings &settings,
		TeagramIconChoice choice) {
	settings.template writePref<int>(
		kTeagramIconChoicePreference,
		static_cast<int>(choice));
	settings.template writePref<bool>(
		kLegacyTeagramIconChoicePreference,
		choice == TeagramIconChoice::TPrimary);
}

} // namespace Core
