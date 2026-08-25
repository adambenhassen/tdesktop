/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_signup_name.h"

#include "intro/intro_signup_password.h"
#include "intro/intro_username_validation.h"
#include "intro/intro_widget.h"
#include "lang/lang_keys.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "styles/style_intro.h"

#include <QtCore/QMetaObject>

namespace Intro {
namespace details {

SignUpNameWidget::SignUpNameWidget(
		QWidget *parent,
		not_null<Main::Account*> account,
		not_null<Data*> data)
: Step(parent, account, data)
, _name(this, st::introName, tr::lng_intro_signup_name_ph())
, _note(this, tr::lng_intro_signup_note(), st::introDescription) {
	setTitleText(tr::lng_intro_signup_name_title());
	setDescriptionText(tr::lng_intro_signup_name_desc(
		tr::now,
		lt_username,
		getData()->phone));
	setErrorCentered(false);

	// Leave one character beyond the accepted limit so submit() can show
	// the localized length error instead of truncating it away.
	_name->setMaxLength(61);
	_name->setAccessibleName(tr::lng_intro_signup_name_ph(tr::now));
	_name->setAccessibleDescription(tr::lng_intro_signup_note(tr::now));
	_note->resizeToWidth(st::introDescription.minWidth);

	_name->changes() | rpl::on_next([=] {
		nameChanged();
	}, _name->lifetime());
	_name->submits() | rpl::on_next([=](Qt::KeyboardModifiers) {
		submit();
	}, _name->lifetime());
}

int SignUpNameWidget::nextButtonTop() const {
	return contentTop() + st::introServerNextTop;
}

int SignUpNameWidget::errorTop() const {
	return contentTop() + st::introSignUpNameErrorTop;
}

QWidget *SignUpNameWidget::firstTabWidget() const {
	return _name.data();
}

void SignUpNameWidget::setInnerFocus() {
	_name->setFocusFast();
}

void SignUpNameWidget::activate() {
	Step::activate();
	_name->setFocusFast();

	if (!getData()->usernameError.isEmpty()) {
		// PHONE_NUMBER_INVALID belongs to the username step. This name step
		// is still on the stack, so let its activation unwind one more level
		// after the password step has already returned here.
		QMetaObject::invokeMethod(this, [=] {
			goBack();
		}, Qt::QueuedConnection);
		return;
	}

	if (!getData()->signupNameError.isEmpty()) {
		const auto text = getData()->signupNameError;
		getData()->signupNameError.clear();
		showNameError(text);
	}
}

void SignUpNameWidget::resizeEvent(QResizeEvent *e) {
	Step::resizeEvent(e);
	_name->moveToLeft(
		contentLeft(),
		contentTop() + st::introStepFieldTop);
	_note->moveToLeft(
		contentLeft() + st::buttonRadius,
		contentTop() + st::introSignUpNoteTop);
}

void SignUpNameWidget::nameChanged() {
	hideError();
	_name->setAccessibleDescription(tr::lng_intro_signup_note(tr::now));
	setAccessibleDescription(QString());
}

void SignUpNameWidget::showNameError(const QString &text) {
	_name->showError();
	_name->setAccessibleDescription(text);
	setAccessibleDescription(text);
	showError(rpl::single(text));
}

void SignUpNameWidget::submit() {
	switch (ValidateSignupName(_name->getLastText())) {
	case SignupNameValidation::Empty:
		showNameError(tr::lng_intro_signup_name_empty(tr::now));
		return;
	case SignupNameValidation::TooLong:
		showNameError(tr::lng_intro_signup_name_long(tr::now));
		return;
	case SignupNameValidation::Valid:
		break;
	}

	hideError();
	setAccessibleDescription(QString());
	getData()->signupName = NormalizeSignupNameInput(_name->getLastText());
	goNext<SignUpPasswordWidget>();
}

} // namespace details
} // namespace Intro
