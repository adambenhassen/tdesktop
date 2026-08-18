/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "intro/intro_step.h"
#include "mtproto/mtproto_custom_server_input.h"

namespace Ui {
class InputField;
class RpWidget;
class LinkButton;
} // namespace Ui

namespace Intro {
namespace details {

class ServerKeyWidget;

class ServerWidget final : public Step {
public:
	ServerWidget(
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

protected:
	void resizeEvent(QResizeEvent *e) override;

private:
	bool _locked = false;
	object_ptr<Ui::InputField> _address;
	object_ptr<Ui::InputField> _key;

};

class ServerKeyWidget final : public Step {
public:
	ServerKeyWidget(
		QWidget *parent,
		not_null<Main::Account*> account,
		not_null<Data*> data);

	bool hasBack() const override {
		return true;
	}

	[[nodiscard]] int nextButtonTop() const override;

	void activate() override;
	void submit() override;

protected:
	void resizeEvent(QResizeEvent *e) override;
	void paintEvent(QPaintEvent *e) override;

private:
	enum class Verdict {
		None,
		Match,
		Mismatch,
	};

	void commitAndAdvance();
	void updateVerdict();
	void paintPanel(QPainter &p);

	MTP::ServerEndpointCheck _endpoint;
	MTP::ServerKeyCheck _keyCheck;

	object_ptr<Ui::RpWidget> _panel;
	object_ptr<Ui::InputField> _compare;
	object_ptr<Ui::LinkButton> _copy;

	Verdict _verdict = Verdict::None;

};

} // namespace details
} // namespace Intro
