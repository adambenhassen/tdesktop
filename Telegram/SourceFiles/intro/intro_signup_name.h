/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "intro/intro_step.h"

namespace Ui {
class FlatLabel;
class InputField;
} // namespace Ui

namespace Intro {
namespace details {

class SignUpNameWidget final : public Step {
public:
	SignUpNameWidget(
		QWidget *parent,
		not_null<Main::Account*> account,
		not_null<Data*> data);

	bool hasBack() const override {
		return true;
	}

	void setInnerFocus() override;
	void activate() override;
	void submit() override;

	[[nodiscard]] int nextButtonTop() const override;
	[[nodiscard]] QWidget *firstTabWidget() const override;

protected:
	void resizeEvent(QResizeEvent *e) override;

private:
	[[nodiscard]] int errorTop() const override;
	void nameChanged();
	void showNameError(const QString &text);

	object_ptr<Ui::InputField> _name;
	object_ptr<Ui::FlatLabel> _note;
};

} // namespace details
} // namespace Intro
