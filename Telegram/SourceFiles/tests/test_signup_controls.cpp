/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/test_main.h"

#include "intro/intro_signup_controls.h"

#include <QLineEdit>
#include <QSize>

namespace Test {
namespace {

void CheckSignupControl(
		QWidget *control,
		not_null<Ui::RpWidget*> step) {
	Expects(control != nullptr);
	Expects(control->isVisibleTo(step));
	Expects(control->isEnabled());
	Expects(control->focusPolicy() != Qt::NoFocus);
	Expects(step->rect().contains(control->geometry()));
}

} // namespace

void RunSignupControlsRegression(not_null<Ui::RpWidget*> root) {
	// These are the two desktop viewport sizes used by the enrollment QA
	// flow. The transition path is hideChildren() followed by the same
	// activation seam used by SignUpNameWidget and SignUpPasswordWidget.
	for (const auto size : { QSize(1024, 768), QSize(1366, 768) }) {
		auto step = new Ui::RpWidget(root);
		step->resize(size);
		step->show();

		auto name = new QLineEdit(step);
		auto password = new QLineEdit(step);
		auto repeat = new QLineEdit(step);
		name->setGeometry(40, 180, 360, 44);
		password->setGeometry(40, 180, 360, 44);
		repeat->setGeometry(40, 240, 360, 44);

		step->hideChildren();
		Intro::details::ShowSignupControls(step);
		CheckSignupControl(name, step);
		CheckSignupControl(password, step);
		CheckSignupControl(repeat, step);

		step->hide();
		delete step;
	}
}

} // namespace Test
