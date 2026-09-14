/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/signup_controls_regression.h"

#include "core/application.h"
#include "intro/intro_signup_name.h"
#include "intro/intro_signup_password.h"
#include "intro/intro_widget.h"
#include "main/main_domain.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/fields/password_input.h"
#include "ui/widgets/rp_window.h"
#include "window/window_controller.h"

#include <QApplication>
#include <QEventLoop>
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

void FinishStepAnimation(not_null<Intro::details::Step*> step) {
	for (auto i = 0; i != 20 && step->animating(); ++i) {
		QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
	}
}

} // namespace

int RunSignupControlsRegression() {
	const auto &domain = Core::App().domain();
	if (!domain.started() || domain.accounts().empty()) {
		return 1;
	}
	auto controller = std::make_unique<Window::Controller>();
	const auto account = not_null<Main::Account*>(
		domain.accounts().front().account.get());

	auto window = std::make_unique<Ui::RpWindow>();
	window->setGeometry({ 100, 100, 1100, 780 });
	window->show();
	QApplication::processEvents();

	for (const auto size : {
		QSize(500, 522),
		QSize(818, 642),
		QSize(1100, 780),
	}) {
		auto intro = std::make_unique<Intro::Widget>(
			window->body(),
			not_null<Window::Controller*>(controller.get()),
			account,
			Intro::EnterPoint::Start,
			nullptr);
		intro->setGeometry({ 0, 0, size.width(), size.height() });
		intro->show();
		QApplication::processEvents();
		intro->startSignupControlsRegressionStep();

		auto name = intro->findChild<Intro::details::SignUpNameWidget*>();
		if (!name) {
			return 1;
		}
		FinishStepAnimation(name);
		if (!CheckSignupControl(name->firstTabWidget(), name)) {
			return 1;
		}

		const auto nameField = dynamic_cast<Ui::InputField*>(
			name->firstTabWidget());
		if (!nameField) {
			return 1;
		}
		nameField->setText(u"Regression User"_q);
		name->submit();

		auto password = intro->findChild<Intro::details::SignUpPasswordWidget*>();
		if (!password) {
			return 1;
		}
		FinishStepAnimation(password);
		if (!CheckSignupControl(password->firstTabWidget(), password)) {
			return 1;
		}

		auto found = 0;
		const auto fields = password->findChildren<QWidget*>(
			QString(),
			Qt::FindDirectChildrenOnly);
		for (const auto field : fields) {
			if (dynamic_cast<Ui::PasswordInput*>(field)
				&& !CheckSignupControl(field, password)) {
				return 1;
			}
			if (dynamic_cast<Ui::PasswordInput*>(field)) {
				++found;
			}
		}
		if (found != 2) {
			return 1;
		}
	}

	window->close();
	return 0;
}
