/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "intro/intro_step.h"
#include "core/core_cloud_password.h"

#include <QtCore/QByteArray>

namespace Ui {
class PasswordInput;
} // namespace Ui

namespace Intro {
namespace details {

class SignUpPasswordWidget final : public Step {
public:
	SignUpPasswordWidget(
		QWidget *parent,
		not_null<Main::Account*> account,
		not_null<Data*> data);

	bool hasBack() const override {
		return _backAvailable.current();
	}

	rpl::producer<bool> backAvailable() const override;

	void setInnerFocus() override;
	void activate() override;
	void cancelled() override;
	void submit() override;

	rpl::producer<QString> nextButtonText() const override;

	[[nodiscard]] int nextButtonTop() const override;
	[[nodiscard]] QWidget *firstTabWidget() const override;

protected:
	void resizeEvent(QResizeEvent *e) override;

private:
	[[nodiscard]] int errorTop() const override;

	void passwordChanged();
	void repeatChanged();
	void clearErrorDescriptions();
	void showPasswordError(
		const QString &text,
		not_null<Ui::PasswordInput*> field);
	void showFormError(const QString &text);

	void signUp();
	void signUpDone(const MTPauth_Authorization &result);
	void signUpFail(const MTP::Error &error);
	void reissueCode();
	void reissueDone(const MTPauth_SentCode &result);
	void reissueFail(const MTP::Error &error);

	void requestPasswordData();
	void passwordDataDone(const MTPaccount_Password &result);
	void passwordDataFail(const MTP::Error &error);
	void sendPasswordUpdate();
	void passwordUpdateDone(const MTPBool &result);
	void passwordUpdateFail(const MTP::Error &error);
	void passwordSaveFailed();
	void routeBackWithUsernameError(const QString &text);
	void routeBackWithNameError(const QString &text);

	object_ptr<Ui::PasswordInput> _password;
	object_ptr<Ui::PasswordInput> _repeat;

	Core::CloudPasswordState _passwordState;
	Core::CloudPasswordAlgo _passwordAlgo;
	bytes::vector _passwordHash;
	QByteArray _passwordBytes;
	MTPauth_Authorization _authorization;

	rpl::variable<bool> _backAvailable = true;
	mtpRequestId _sentRequest = 0;
	bool _signupDone = false;
	bool _reissuedOnce = false;
};

} // namespace details
} // namespace Intro
