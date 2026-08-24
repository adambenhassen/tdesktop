/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "intro/intro_step.h"
#include "base/timer.h"

namespace Ui {
class FlatLabel;
class InputField;
} // namespace Ui

namespace Intro {
namespace details {

// The username step: the one identity question this flow asks. Whether
// the name turns out to exist is decided by auth.signIn, not by the
// user, so there is no sign-in / registration chooser ahead of it.
// auth.sendCode runs invisibly inside submit(), immediately before
// auth.signIn; the code itself is never shown or typed.
class UsernameWidget final : public Step {
public:
	UsernameWidget(
		QWidget *parent,
		not_null<Main::Account*> account,
		not_null<Data*> data);

	bool hasBack() const override {
		return true;
	}

	[[nodiscard]] int nextButtonTop() const override;
	[[nodiscard]] int errorTop() const override;

	void setInnerFocus() override;
	void activate() override;
	void submit() override;
	void finished() override;
	void cancelled() override;

	[[nodiscard]] rpl::producer<QString> nextButtonText() const override;

	[[nodiscard]] QWidget *firstTabWidget() const override;

protected:
	void resizeEvent(QResizeEvent *e) override;

private:
	void usernameChanged();
	void requestCode();
	void signIn();
	void sendCodeDone(const MTPauth_SentCode &result);
	void requestFail(const MTP::Error &error);
	void signInDone(const MTPauth_Authorization &result);
	void signInFail(const MTP::Error &error);
	void carryForwardAndFinish(const MTPauth_Authorization &result);
	void passwordNeeded();
	void reissueAndRetry();

	// Pending state: the field stays readable (read-only, not disabled),
	// the button says why nothing happens, and a status line sits in the
	// error slot until either branch of the flow answers.
	void startPending();
	void stopPending();
	void showStatus(const QString &text);
	void hideStatus();
	void announceStatus();
	void checkRequest();

	void fail(const QString &text);

	object_ptr<Ui::InputField> _username;
	object_ptr<Ui::FlatLabel> _status = { nullptr };

	base::Timer _checkRequestTimer;
	mtpRequestId _sentRequest = 0;
	QString _sentUsername;
	QByteArray _sentHash;
	rpl::variable<bool> _pending = false;
	bool _reissuedOnce = false;
	bool _escalated = false;
	int _waitingSeconds = 0;

};

} // namespace details
} // namespace Intro
