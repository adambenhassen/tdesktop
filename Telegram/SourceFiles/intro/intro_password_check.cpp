/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_password_check.h"

#include "intro/intro_auth_validation.h"
#include "intro/intro_widget.h"
#include "core/core_cloud_password.h"
#include "lang/lang_keys.h"
#include "ui/widgets/fields/password_input.h"
#include "ui/widgets/labels.h"
#include "base/random.h"
#include "styles/style_intro.h"
#include "ui/text/format_values.h"

namespace Intro {
namespace details {

PasswordCheckWidget::PasswordCheckWidget(
	QWidget *parent,
	not_null<Main::Account*> account,
	not_null<Data*> data)
: Step(parent, account, data)
, _passwordState(getData()->pwdState)
, _pwdField(this, st::introPassword, tr::lng_intro_signin_ph())
, _pwdHint(this, st::introPasswordHint)
, _noReset(this, tr::lng_intro_signin_noreset(), st::introDescription) {
	Expects(_passwordState.hasPassword);

	Lang::Updated(
	) | rpl::on_next([=] {
		refreshLang();
	}, lifetime());

	setTitleText(tr::lng_intro_signin_title());
	setDescriptionText(tr::lng_intro_signin_desc(
		lt_username,
		rpl::single(getData()->phone)));
	setErrorCentered(false);

	_pwdField->setAccessibleName(tr::lng_intro_signin_ph(tr::now));
	connect(_pwdField, &Ui::PasswordInput::changed, [=] {
		passwordChanged();
	});
	connect(_pwdField, &Ui::PasswordInput::submitted, [=] {
		submit();
	});

	if (_passwordState.hint.isEmpty()) {
		_pwdHint->hide();
	} else {
		_pwdHint->setText(tr::lng_intro_signin_hint(
			tr::now,
			lt_password_hint,
			_passwordState.hint));
	}
	_noReset->resizeToWidth(st::introDescription.minWidth);
	updateAccessibleDescription();

	setMouseTracking(true);
}

void PasswordCheckWidget::refreshLang() {
	_pwdField->setAccessibleName(tr::lng_intro_signin_ph(tr::now));
	_noReset->setText(tr::lng_intro_signin_noreset(tr::now));
	if (!_passwordState.hint.isEmpty()) {
		_pwdHint->setText(tr::lng_intro_signin_hint(
			tr::now,
			lt_password_hint,
			_passwordState.hint));
	}
	updateAccessibleDescription();
	updateControlsGeometry();
}

int PasswordCheckWidget::errorTop() const {
	return contentTop() + st::introSignInErrorTop;
}

int PasswordCheckWidget::nextButtonTop() const {
	return contentTop() + st::introServerNextTop;
}

QWidget *PasswordCheckWidget::firstTabWidget() const {
	return _pwdField.data();
}

void PasswordCheckWidget::resizeEvent(QResizeEvent *e) {
	Step::resizeEvent(e);
	updateControlsGeometry();
}

void PasswordCheckWidget::updateControlsGeometry() {
	_pwdField->moveToLeft(
		contentLeft(),
		contentTop() + st::introStepFieldTop);
	_pwdHint->moveToLeft(
		contentLeft() + st::buttonRadius,
		contentTop() + st::introSignInHintTop);
	_noReset->moveToLeft(
		contentLeft() + st::buttonRadius,
		contentTop() + st::introSignInNoteTop);
}

void PasswordCheckWidget::setInnerFocus() {
	_pwdField->setFocusFast();
}

void PasswordCheckWidget::activate() {
	Step::activate();
	_pwdField->show();
	if (_passwordState.hint.isEmpty()) {
		_pwdHint->hide();
	} else {
		_pwdHint->show();
	}
	_noReset->show();
	setInnerFocus();
}

void PasswordCheckWidget::cancelled() {
	api().request(base::take(_sentRequest)).cancel();
}

void PasswordCheckWidget::pwdSubmitDone(
		const MTPauth_Authorization &result) {
	_sentRequest = 0;
	finish(result);
}

void PasswordCheckWidget::pwdSubmitFail(const MTP::Error &error) {
	_sentRequest = 0;
	const auto &type = error.type();
	switch (ClassifySigninPasswordFailure(type)) {
	case SigninPasswordFailure::Flood:
		showPasswordError(tr::lng_intro_signin_flood(
			tr::now,
			lt_duration,
			Ui::FormatDurationWords(FloodWaitSeconds(type))));
		return;
	case SigninPasswordFailure::WrongPassword:
		showPasswordError(tr::lng_intro_signin_wrong(tr::now));
		_pwdField->selectAll();
		return;
	case SigninPasswordFailure::PasswordEmpty:
	case SigninPasswordFailure::AuthKeyUnregistered:
		goBack();
		return;
	case SigninPasswordFailure::SrpIdInvalid:
		handleSrpIdInvalid();
		return;
	case SigninPasswordFailure::Other:
		LOG(("Intro Password Error: checkPassword failed with %1 (%2)")
			.arg(type)
			.arg(error.code()));
		serverError();
		_pwdField->setFocus();
		return;
	}
}

void PasswordCheckWidget::handleSrpIdInvalid() {
	const auto now = crl::now();
	if (_lastSrpIdInvalidTime > 0
		&& now - _lastSrpIdInvalidTime < Core::kHandleSrpIdInvalidTimeout) {
		_passwordState.mtp.request.id = 0;
		serverError();
	} else {
		_lastSrpIdInvalidTime = now;
		requestPasswordData();
	}
}

void PasswordCheckWidget::checkPasswordHash() {
	if (_passwordState.mtp.request.id) {
		passwordChecked();
	} else {
		requestPasswordData();
	}
}

void PasswordCheckWidget::requestPasswordData() {
	api().request(base::take(_sentRequest)).cancel();
	_sentRequest = api().request(
		MTPaccount_GetPassword()
	).done([=](const MTPaccount_Password &result) {
		_sentRequest = 0;
		result.match([&](const MTPDaccount_password &data) {
			base::RandomAddSeed(bytes::make_span(data.vsecure_random().v));
			_passwordState = Core::ParseCloudPasswordState(data);
			passwordChecked();
		});
	}).fail([=](const MTP::Error &error) {
		passwordDataFail(error);
	}).handleAllErrors().send();
}

void PasswordCheckWidget::passwordDataFail(const MTP::Error &error) {
	_sentRequest = 0;
	switch (ClassifySigninPasswordDataFailure(error.type())) {
	case SigninPasswordDataFailure::Flood:
		showPasswordError(tr::lng_intro_signin_flood(
			tr::now,
			lt_duration,
			Ui::FormatDurationWords(FloodWaitSeconds(error.type()))));
		return;
	case SigninPasswordDataFailure::Other:
		LOG(("Intro Password Error: account.getPassword failed with %1 (%2)")
			.arg(error.type())
			.arg(error.code()));
		serverError();
		_pwdField->setFocus();
		return;
	}
}

void PasswordCheckWidget::passwordChecked() {
	const auto check = Core::ComputeCloudPasswordCheck(
		_passwordState.mtp.request,
		_passwordHash);
	if (!check) {
		return serverError();
	}
	_passwordState.mtp.request.id = 0;
	_sentRequest = api().request(
		MTPauth_CheckPassword(check.result)
	).done([=](const MTPauth_Authorization &result) {
		pwdSubmitDone(result);
	}).fail([=](const MTP::Error &error) {
		pwdSubmitFail(error);
	}).handleAllErrors().send();
}

void PasswordCheckWidget::serverError() {
	showError(tr::lng_intro_server_error());
}

void PasswordCheckWidget::updateAccessibleDescription() {
	auto description = tr::lng_intro_signin_noreset(tr::now);
	if (!_passwordState.hint.isEmpty()) {
		description = tr::lng_intro_signin_hint(
			tr::now,
			lt_password_hint,
			_passwordState.hint)
			+ u' '
			+ description;
	}
	_pwdField->setAccessibleDescription(description);
}

void PasswordCheckWidget::passwordChanged() {
	hideError();
	updateAccessibleDescription();
	setAccessibleDescription(QString());
}

void PasswordCheckWidget::showPasswordError(const QString &text) {
	_pwdField->showError();
	_pwdField->setAccessibleDescription(text);
	setAccessibleDescription(text);
	showError(rpl::single(text));
}

void PasswordCheckWidget::submit() {
	if (_sentRequest) {
		return;
	}
	const auto password = _pwdField->getLastText();
	if (ValidateSigninPassword(password)
		== SigninPasswordValidation::Empty) {
		showPasswordError(tr::lng_intro_signin_empty(tr::now));
		return;
	}

	hideError();
	updateAccessibleDescription();
	setAccessibleDescription(QString());
	const auto passwordBytes = password.toUtf8();
	_passwordHash = Core::ComputeCloudPasswordHash(
		_passwordState.mtp.request.algo,
		bytes::make_span(passwordBytes));
	checkPasswordHash();
}

rpl::producer<QString> PasswordCheckWidget::nextButtonText() const {
	return tr::lng_intro_signin_button();
}

} // namespace details
} // namespace Intro
