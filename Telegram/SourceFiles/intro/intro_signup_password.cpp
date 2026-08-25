/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_signup_password.h"

#include "config.h"
#include "intro/intro_username_validation.h"
#include "intro/intro_widget.h"
#include "lang/lang_keys.h"
#include "main/main_account.h"
#include "mtproto/type_utils.h"
#include "ui/widgets/fields/password_input.h"
#include "styles/style_intro.h"
#include "base/bytes.h"
#include "base/random.h"
#include "ui/text/format_values.h"

#include <variant>

namespace Intro {
namespace details {

SignUpPasswordWidget::SignUpPasswordWidget(
		QWidget *parent,
		not_null<Main::Account*> account,
		not_null<Data*> data)
: Step(parent, account, data)
, _password(
	this,
	st::introPassword,
	tr::lng_intro_signup_pwd_ph())
, _repeat(
	this,
	st::introPassword,
	tr::lng_intro_signup_pwd_ph2()) {
	setTitleText(tr::lng_intro_signup_pwd_title());
	setDescriptionText(tr::lng_intro_signup_pwd_desc());
	setErrorCentered(false);

	_password->setMaxLength(256);
	_repeat->setMaxLength(256);
	_password->setAccessibleName(tr::lng_intro_signup_pwd_ph(tr::now));
	_repeat->setAccessibleName(tr::lng_intro_signup_pwd_ph2(tr::now));
	_password->setAccessibleDescription(
		tr::lng_intro_signup_pwd_a11y(tr::now));
	_repeat->setAccessibleDescription(
		tr::lng_intro_signup_pwd_repeat_a11y(tr::now));

	setTabOrder(_password, _repeat);
	connect(_password, &Ui::PasswordInput::changed, [=] {
		passwordChanged();
	});
	connect(_repeat, &Ui::PasswordInput::changed, [=] {
		repeatChanged();
	});
	connect(_password, &Ui::PasswordInput::submitted, [=] {
		if (_repeat->getLastText().isEmpty()) {
			_repeat->setFocusFast();
		} else {
			submit();
		}
	});
	connect(_repeat, &Ui::PasswordInput::submitted, [=] {
		submit();
	});
}

int SignUpPasswordWidget::nextButtonTop() const {
	return contentTop() + st::introServerNextTop;
}

int SignUpPasswordWidget::errorTop() const {
	return contentTop() + st::introSignUpPasswordErrorTop;
}

QWidget *SignUpPasswordWidget::firstTabWidget() const {
	return _password.data();
}

rpl::producer<bool> SignUpPasswordWidget::backAvailable() const {
	return _backAvailable.value();
}

void SignUpPasswordWidget::setInnerFocus() {
	_password->setFocusFast();
}

void SignUpPasswordWidget::activate() {
	Step::activate();
	_password->setFocusFast();
}

void SignUpPasswordWidget::resizeEvent(QResizeEvent *e) {
	Step::resizeEvent(e);
	_password->moveToLeft(
		contentLeft(),
		contentTop() + st::introStepFieldTop);
	_repeat->moveToLeft(
		contentLeft(),
		contentTop() + st::introStepFieldTop + st::introName.heightMin
			+ st::introPhoneTop);
}

void SignUpPasswordWidget::passwordChanged() {
	hideError();
	_passwordHash.clear();
	clearErrorDescriptions();
}

void SignUpPasswordWidget::repeatChanged() {
	hideError();
	_passwordHash.clear();
	clearErrorDescriptions();
}

void SignUpPasswordWidget::clearErrorDescriptions() {
	_password->setAccessibleDescription(
		tr::lng_intro_signup_pwd_a11y(tr::now));
	_repeat->setAccessibleDescription(
		tr::lng_intro_signup_pwd_repeat_a11y(tr::now));
	setAccessibleDescription(QString());
}

void SignUpPasswordWidget::showPasswordError(
		const QString &text,
		not_null<Ui::PasswordInput*> field) {
	field->showError();
	field->setAccessibleDescription(text);
	setAccessibleDescription(text);
	showError(rpl::single(text));
}

void SignUpPasswordWidget::showFormError(const QString &text) {
	setAccessibleDescription(text);
	showError(rpl::single(text));
}

void SignUpPasswordWidget::submit() {
	if (_sentRequest) {
		return;
	}

	const auto password = _password->getLastText();
	const auto repeat = _repeat->getLastText();
	switch (ValidateSignupPassword(password, repeat)) {
	case SignupPasswordValidation::Empty:
		showPasswordError(
			tr::lng_intro_signup_pwd_empty(tr::now),
			_password);
		return;
	case SignupPasswordValidation::TooShort:
		showPasswordError(
			tr::lng_intro_signup_pwd_short(tr::now),
			_password);
		return;
	case SignupPasswordValidation::RepeatEmpty:
		showPasswordError(
			tr::lng_intro_signup_pwd_repeat(tr::now),
			_repeat);
		_repeat->setFocusFast();
		return;
	case SignupPasswordValidation::Mismatch:
		_repeat->selectAll();
		showPasswordError(
			tr::lng_intro_signup_pwd_mismatch(tr::now),
			_repeat);
		_repeat->setFocusFast();
		return;
	case SignupPasswordValidation::Valid:
		break;
	}

	hideError();
	clearErrorDescriptions();
	_passwordBytes = password.toUtf8();

	if (_signupDone && !_passwordHash.empty()) {
		sendPasswordUpdate();
	} else if (_signupDone) {
		requestPasswordData();
	} else {
		signUp();
	}
}

void SignUpPasswordWidget::signUp() {
	_sentRequest = api().request(MTPauth_SignUp(
		MTP_flags(0),
		MTP_string(getData()->phone),
		MTP_bytes(getData()->phoneHash),
		MTP_string(getData()->signupName),
		MTP_string(QString())
	)).done([=](const MTPauth_Authorization &result) {
		_sentRequest = 0;
		signUpDone(result);
	}).fail([=](const MTP::Error &error) {
		_sentRequest = 0;
		signUpFail(error);
	}).handleAllErrors().send();
}

void SignUpPasswordWidget::signUpDone(
		const MTPauth_Authorization &result) {
	// The account is provisional as soon as signUp answers successfully.
	// Withdraw Back before asking for anything else, so Escape and the
	// button cannot abandon a username that has no usable password yet.
	_signupDone = true;
	_backAvailable = false;
	_authorization = result;
	requestPasswordData();
}

void SignUpPasswordWidget::signUpFail(const MTP::Error &error) {
	const auto &type = error.type();
	if (type == u"INPUT_REQUEST_INVALID"_q) {
		showFormError(tr::lng_intro_signup_closed(tr::now));
	} else if (type == u"USERNAME_OCCUPIED"_q) {
		showFormError(tr::lng_intro_signup_taken(
			tr::now,
			lt_username,
			getData()->phone));
	} else if (type == u"PHONE_NUMBER_INVALID"_q) {
		routeBackWithUsernameError(
			tr::lng_intro_username_unavailable(tr::now));
	} else if (type == u"FIRSTNAME_INVALID"_q) {
		routeBackWithNameError(
			tr::lng_intro_signup_name_bad(tr::now));
	} else if (type == u"PHONE_CODE_INVALID"_q
		|| type == u"PHONE_CODE_EXPIRED"_q) {
		reissueCode();
	} else if (MTP::IsFloodError(error)) {
		showFormError(tr::lng_intro_signup_flood(
			tr::now,
			lt_duration,
			Ui::FormatDurationWords(FloodWaitSeconds(type))));
	} else {
		LOG(("Intro Sign-up Error: auth.signUp failed with %1 (%2)")
			.arg(type)
			.arg(error.code()));
		showFormError(tr::lng_intro_server_error(tr::now));
	}
}

void SignUpPasswordWidget::reissueCode() {
	if (_reissuedOnce) {
		showFormError(tr::lng_intro_signup_expired(tr::now));
		return;
	}
	_reissuedOnce = true;
	getData()->usernameCode.drop();
	_sentRequest = api().request(MTPauth_SendCode(
		MTP_string(getData()->phone),
		MTP_int(ApiId),
		MTP_string(ApiHash),
		MTP_codeSettings(
			MTP_flags(0),
			MTPVector<MTPbytes>(),
			MTPstring(),
			MTPBool())
	)).done([=](const MTPauth_SentCode &result) {
		_sentRequest = 0;
		reissueDone(result);
	}).fail([=](const MTP::Error &error) {
		_sentRequest = 0;
		reissueFail(error);
	}).handleAllErrors().send();
}

void SignUpPasswordWidget::reissueDone(const MTPauth_SentCode &result) {
	result.match([&](const MTPDauth_sentCode &data) {
		const auto hash = qba(data.vphone_code_hash());
		if (hash.isEmpty()) {
			showFormError(tr::lng_intro_signup_expired(tr::now));
			return;
		}
		getData()->phoneHash = hash;
		signUp();
	}, [&](const MTPDauth_sentCodeSuccess &) {
		showFormError(tr::lng_intro_signup_expired(tr::now));
	}, [&](const MTPDauth_sentCodePaymentRequired &) {
		showFormError(tr::lng_intro_signup_expired(tr::now));
	});
}

void SignUpPasswordWidget::reissueFail(const MTP::Error &error) {
	if (MTP::IsFloodError(error)) {
		showFormError(tr::lng_intro_signup_flood(
			tr::now,
			lt_duration,
			Ui::FormatDurationWords(FloodWaitSeconds(error.type()))));
	} else {
		LOG(("Intro Sign-up Error: auth.sendCode reissue failed with %1 (%2)")
			.arg(error.type())
			.arg(error.code()));
		showFormError(tr::lng_intro_server_error(tr::now));
	}
}

void SignUpPasswordWidget::requestPasswordData() {
	_sentRequest = api().request(MTPaccount_GetPassword(
	)).done([=](const MTPaccount_Password &result) {
		_sentRequest = 0;
		passwordDataDone(result);
	}).fail([=](const MTP::Error &error) {
		_sentRequest = 0;
		passwordDataFail(error);
	}).handleAllErrors().send();
}

void SignUpPasswordWidget::passwordDataDone(
		const MTPaccount_Password &result) {
	result.match([&](const MTPDaccount_password &data) {
		base::RandomAddSeed(bytes::make_span(data.vsecure_random().v));
		_passwordState = Core::ParseCloudPasswordState(data);
		if (!std::holds_alternative<Core::CloudPasswordAlgoModPow>(
			_passwordState.mtp.newPassword)) {
			LOG(("Intro Sign-up Error: getPassword returned no new algorithm."));
			showFormError(tr::lng_intro_retry(tr::now));
			return;
		}

		_passwordAlgo = _passwordState.mtp.newPassword;
		const auto digest = Core::ComputeCloudPasswordDigest(
			_passwordAlgo,
			bytes::make_span(_passwordBytes));
		if (digest.modpow.empty() || digest.salt1.empty()) {
			showFormError(tr::lng_intro_retry(tr::now));
			return;
		}
		// Serialize the exact salt returned with the digest, keeping the
		// verifier and KDF algorithm coupled if the digest path changes.
		std::get<Core::CloudPasswordAlgoModPow>(_passwordAlgo).salt1
			= digest.salt1;
		_passwordHash = digest.modpow;
		sendPasswordUpdate();
	});
}

void SignUpPasswordWidget::passwordDataFail(const MTP::Error &error) {
	LOG(("Intro Sign-up Error: account.getPassword failed with %1 (%2)")
		.arg(error.type())
		.arg(error.code()));
	showFormError(tr::lng_intro_server_error(tr::now));
}

void SignUpPasswordWidget::sendPasswordUpdate() {
	if (_sentRequest || _passwordHash.empty()) {
		return;
	}

	using Flag = MTPDaccount_passwordInputSettings::Flag;
	const auto flags = Flag::f_new_algo
		| Flag::f_new_password_hash
		| Flag::f_hint
		| Flag::f_email;
	const auto settings = MTP_account_passwordInputSettings(
		MTP_flags(flags),
		Core::PrepareCloudPasswordAlgo(_passwordAlgo),
		MTP_bytes(_passwordHash),
		MTP_string(QString()),
		MTP_string(QString()),
		MTPSecureSecretSettings());

	_sentRequest = api().request(MTPaccount_UpdatePasswordSettings(
		MTP_inputCheckPasswordEmpty(),
		settings
	)).done([=](const MTPBool &result) {
		_sentRequest = 0;
		passwordUpdateDone(result);
	}).fail([=](const MTP::Error &error) {
		_sentRequest = 0;
		passwordUpdateFail(error);
	}).handleAllErrors().send();
}

void SignUpPasswordWidget::passwordUpdateDone(const MTPBool &result) {
	if (mtpIsTrue(result)) {
		// The provisional account is usable only after this exact success.
		finish(_authorization);
	} else {
		passwordSaveFailed();
	}
}

void SignUpPasswordWidget::passwordUpdateFail(const MTP::Error &error) {
	LOG(("Intro Sign-up Error: account.updatePasswordSettings failed with "
		"%1 (%2)").arg(error.type()).arg(error.code()));
	switch (ClassifySignupPasswordUpdateFailure(error.type())) {
	case SignupPasswordUpdateFailure::Flood:
		showFormError(tr::lng_intro_signup_flood(
			tr::now,
			lt_duration,
			Ui::FormatDurationWords(FloodWaitSeconds(error.type()))));
		return;
	case SignupPasswordUpdateFailure::InvalidVerifier:
		showFormError(tr::lng_intro_retry(tr::now));
		return;
	case SignupPasswordUpdateFailure::Other:
		passwordSaveFailed();
		return;
	}
}

void SignUpPasswordWidget::passwordSaveFailed() {
	showFormError(tr::lng_intro_signup_pwd_unsaved(tr::now));
}

void SignUpPasswordWidget::routeBackWithUsernameError(
		const QString &text) {
	getData()->usernameError = text;
	goBack();
}

void SignUpPasswordWidget::routeBackWithNameError(
		const QString &text) {
	getData()->signupNameError = text;
	goBack();
}

void SignUpPasswordWidget::cancelled() {
	if (_sentRequest) {
		api().request(base::take(_sentRequest)).cancel();
	}
}

rpl::producer<QString> SignUpPasswordWidget::nextButtonText() const {
	return tr::lng_intro_signup_create();
}

} // namespace details
} // namespace Intro
