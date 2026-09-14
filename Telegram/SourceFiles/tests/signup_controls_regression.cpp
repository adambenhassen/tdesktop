/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/signup_controls_regression.h"

#include "intro/intro_signup_name.h"
#include "intro/intro_signup_password.h"
#include "intro/intro_widget.h"
#include "ui/widgets/fields/password_input.h"
#include "ui/widgets/rp_window.h"

#include <QApplication>
#include <QSize>

namespace {

bool CheckSignupControl(
		QWidget *control,
		not_null<Intro::details::Step*> step) {
	if (!control
		|| !control->isVisibleTo(step)
		|| !control->isEnabled()
		|| control->focusPolicy() == Qt::NoFocus
		|| !step->rect().contains(control->geometry())) {
		return false;
	}

	control->setFocus(Qt::OtherFocusReason);
	QApplication::processEvents();
	const auto focused = QApplication::focusWidget();
	if (focused != control && !control->isAncestorOf(focused)) {
		return false;
	}

	const auto center = control->mapToGlobal(control->rect().center());
	const auto hit = QApplication::widgetAt(center);
	return hit && (hit == control || control->isAncestorOf(hit));
}

} // namespace

int RunSignupControlsRegression() {
	auto window = std::make_unique<Ui::RpWindow>();
	window->setGeometry({ 100, 100, 1100, 780 });
	window->show();
	QApplication::processEvents();

	const auto account = not_null<Main::Account*>(
		reinterpret_cast<Main::Account*>(quintptr(1)));
	const auto controller = not_null<Window::Controller*>(
		reinterpret_cast<Window::Controller*>(quintptr(1)));
	auto data = Intro::details::Data{ controller };
	data.phone = u"+15550000000"_q;

	for (const auto size : {
		QSize(500, 522),
		QSize(818, 642),
		QSize(1100, 780),
	}) {
		auto name = new Intro::details::SignUpNameWidget(
			window->body(),
			account,
			&data);
		name->resize(size);
		name->showAnimated(Intro::details::Animate::Forward);
		if (!CheckSignupControl(name->firstTabWidget(), name)) {
			delete name;
			return 1;
		}

		auto password = new Intro::details::SignUpPasswordWidget(
			window->body(),
			account,
			&data);
		password->resize(size);
		password->showAnimated(Intro::details::Animate::Forward);
		if (!CheckSignupControl(password->firstTabWidget(), password)) {
			delete name;
			delete password;
			return 1;
		}

		auto found = 0;
		const auto fields = password->findChildren<QWidget*>(
			QString(),
			Qt::FindDirectChildrenOnly);
		for (const auto field : fields) {
			if (dynamic_cast<Ui::PasswordInput*>(field)
				&& !CheckSignupControl(field, password)) {
				delete name;
				delete password;
				return 1;
			}
			if (dynamic_cast<Ui::PasswordInput*>(field)) {
				++found;
			}
		}
		if (found != 2) {
			delete name;
			delete password;
			return 1;
		}

		delete name;
		delete password;
	}

	window->close();
	return 0;
}
