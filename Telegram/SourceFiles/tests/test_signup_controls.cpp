/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/test_main.h"

#include "intro/intro_signup_name.h"
#include "intro/intro_signup_password.h"
#include "intro/intro_widget.h"
#include "ui/widgets/fields/password_input.h"

#include <QApplication>
#include <QSize>

namespace Test {
namespace {

void CheckSignupControl(
		QWidget *control,
		not_null<Intro::details::Step*> step) {
	Expects(control != nullptr);
	Expects(control->isVisibleTo(step));
	Expects(control->isEnabled());
	Expects(control->focusPolicy() != Qt::NoFocus);
	Expects(step->rect().contains(control->geometry()));

	control->setFocus(Qt::OtherFocusReason);
	QApplication::processEvents();
	const auto focused = QApplication::focusWidget();
	Expects(focused == control || control->isAncestorOf(focused));
}

} // namespace

void RunSignupControlsRegression(not_null<Ui::RpWidget*> root) {
	const auto account = not_null<Main::Account*>(
		reinterpret_cast<Main::Account*>(quintptr(1)));
	const auto controller = not_null<Window::Controller*>(
		reinterpret_cast<Window::Controller*>(quintptr(1)));
	auto data = Intro::details::Data{ controller };
	data.phone = u"+15550000000"_q;

	// Drive the actual signup steps through Step::showAnimated(). The
	// production transition hides every child before the arriving step is
	// usable, so this catches a regression in either real activator.
	for (const auto size : { QSize(500, 522), QSize(818, 642), QSize(1100, 780) }) {
		auto name = new Intro::details::SignUpNameWidget(
			root,
			account,
			&data);
		name->resize(size);
		name->showAnimated(Intro::details::Animate::Forward);
		CheckSignupControl(name->firstTabWidget(), name);

		auto password = new Intro::details::SignUpPasswordWidget(
			root,
			account,
			&data);
		password->resize(size);
		password->showAnimated(Intro::details::Animate::Forward);
		CheckSignupControl(password->firstTabWidget(), password);
		const auto fields = password->findChildren<QWidget*>(
			QString(),
			Qt::FindDirectChildrenOnly);
		auto found = 0;
		for (const auto field : fields) {
			if (dynamic_cast<Ui::PasswordInput*>(field)) {
				++found;
				CheckSignupControl(field, password);
			}
		}
		Expects(found == 2);

		name->hide();
		password->hide();
		delete name;
		delete password;
	}
}

} // namespace Test
