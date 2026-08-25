/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "intro/intro_step.h"
#include "core/core_cloud_password.h"
#include "mtproto/sender.h"
#include "base/timer.h"

namespace Ui {
class PasswordInput;
} // namespace Ui

namespace Intro {
namespace details {

class PasswordCheckWidget final : public Step {
public:
	PasswordCheckWidget(
		QWidget *parent,
		not_null<Main::Account*> account,
		not_null<Data*> data);

	void setInnerFocus() override;
	void activate() override;
	void cancelled() override;
	void submit() override;
	rpl::producer<QString> nextButtonText() const override;
	[[nodiscard]] int nextButtonTop() const override;
	[[nodiscard]] QWidget *firstTabWidget() const override;

	bool hasBack() const override {
		return true;
	}

protected:
	void resizeEvent(QResizeEvent *e) override;

private:
	int errorTop() const override;

	void refreshLang();
	void updateControlsGeometry();
	void updateAccessibleDescription();
	void passwordChanged();
	void showPasswordError(const QString &text);

	void pwdSubmitDone(const MTPauth_Authorization &result);
	void pwdSubmitFail(const MTP::Error &error);

	void handleSrpIdInvalid();
	void requestPasswordData();
	void checkPasswordHash();
	void passwordChecked();
	void serverError();

	Core::CloudPasswordState _passwordState;
	crl::time _lastSrpIdInvalidTime = 0;
	bytes::vector _passwordHash;

	object_ptr<Ui::PasswordInput> _pwdField;
	object_ptr<Ui::FlatLabel> _pwdHint;
	object_ptr<Ui::FlatLabel> _noReset;
	mtpRequestId _sentRequest = 0;

};

} // namespace details
} // namespace Intro
