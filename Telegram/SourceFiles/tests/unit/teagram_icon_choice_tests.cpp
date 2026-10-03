/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "core/core_settings.h"
#include "core/teagram_icon_choice.h"

TEST_CASE(TeagramIconChoiceDefaultsToMug) {
	auto settings = Core::Settings();
	CHECK(Core::ReadTeagramIconChoice(settings)
		== Core::TeagramIconChoice::Mug);
}

TEST_CASE(TeagramIconChoicePersistsAcrossSettingsReload) {
	const auto roundTrip = [](Core::TeagramIconChoice choice) {
		auto settings = Core::Settings();
		Core::WriteTeagramIconChoice(settings, choice);
		const auto serialized = settings.serialize();

		auto reloaded = Core::Settings();
		reloaded.addFromSerialized(serialized);
		return Core::ReadTeagramIconChoice(reloaded);
	};
	CHECK(roundTrip(Core::TeagramIconChoice::T)
		== Core::TeagramIconChoice::T);
	CHECK(roundTrip(Core::TeagramIconChoice::Mug)
		== Core::TeagramIconChoice::Mug);
}
