/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "core/teagram_icon_choice.h"

#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <type_traits>

namespace {

class Preferences final {
public:
	template <typename Type>
	void writePref(std::string_view key, Type value) {
		static_assert(std::is_same_v<Type, bool>);
		_values[std::string(key)] = value;
	}

	template <typename Type>
	[[nodiscard]] Type readPref(std::string_view key, Type fallback = {}) const {
		static_assert(std::is_same_v<Type, bool>);
		const auto i = _values.find(key);
		return (i == end(_values)) ? fallback : Type(i->second);
	}

private:
	std::map<std::string, bool, std::less<>> _values;

};

TEST_CASE(TeagramIconChoiceDefaultsToMug) {
	auto preferences = Preferences();
	CHECK(Core::ReadTeagramIconChoice(preferences)
		== Core::TeagramIconChoice::Mug);
}

TEST_CASE(TeagramIconChoicePreferenceRoundTrips) {
	auto preferences = Preferences();
	Core::WriteTeagramIconChoice(preferences, Core::TeagramIconChoice::T);
	CHECK(Core::ReadTeagramIconChoice(preferences)
		== Core::TeagramIconChoice::T);

	Core::WriteTeagramIconChoice(preferences, Core::TeagramIconChoice::Mug);
	CHECK(Core::ReadTeagramIconChoice(preferences)
		== Core::TeagramIconChoice::Mug);
}

} // namespace
