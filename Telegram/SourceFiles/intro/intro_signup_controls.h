/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "ui/rp_widget.h"

namespace Intro::details {

// Step::showAnimated() hides the step's children for the transition
// snapshot. Signup activators and the UI regression use this one production
// seam to restore controls when the animation has completed.
inline void ShowSignupControls(not_null<Ui::RpWidget*> step) {
	step->showChildren();
}

} // namespace Intro::details
