/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/sender.h"
#include "intro/intro_auth_validation.h"
#include "ui/rp_widget.h"
#include "ui/effects/animations.h"
#include "core/core_cloud_password.h"
#include "media/player/media_player_float.h"

namespace style {
struct RoundButton;
} // namespace style

namespace Main {
class Account;
} // namespace Main

namespace Ui {
class IconButton;
class RoundButton;
class LinkButton;
class FlatLabel;
template <typename Widget>
class FadeWrap;
} // namespace Ui

namespace Window {
class ConnectionState;
class Controller;
class SlideAnimation;
} // namespace Window

namespace Intro {
namespace details {

struct Data {
	const not_null<Window::Controller*> controller;

	base::weak_ptr<Main::Account> accountBeforeIntro;

	QString phone;
	QByteArray phoneHash;

	Core::CloudPasswordState pwdState;

	// Set by ServerWidget on valid input, consumed by ServerKeyWidget.
	QString serverAddress;
	QString serverPem;

	// The phone_code_hash UsernameWidget obtained for its username, so
	// a back-and-forward loop reuses it instead of burning another
	// shared per-IP sendCode call. Fresh for 4 of the server's
	// 5-minute codeTTL, and only against the server that issued it —
	// Back to the server step can commit a different pair inside that
	// window. See UsernameCodeCache.
	UsernameCodeCache usernameCode;

	// Registration values shared by the two custom steps. The server pair
	// and the username hash are already committed before the name step.
	QString signupName;
	QString usernameError;
	QString signupNameError;

};

enum class StackAction {
	Back,
	Forward,
	Replace,
};

enum class Animate {
	Back,
	Forward,
};

class Step;

} // namespace details

enum class EnterPoint : uchar {
	Start,
};

class Widget
	: public Ui::RpWidget
	, private Media::Player::FloatDelegate
	, private Media::Player::FloatSectionDelegate {
public:
	Widget(
		QWidget *parent,
		not_null<Window::Controller*> controller,
		not_null<Main::Account*> account,
		EnterPoint point,
		Main::Account *accountBeforeIntro);
	~Widget();

	void showAnimated(QPixmap oldContentCache, bool back = false);

	void setInnerFocus();

	[[nodiscard]] rpl::producer<> showSettingsRequested() const;

protected:
	void paintEvent(QPaintEvent *e) override;
	void resizeEvent(QResizeEvent *e) override;
	void keyPressEvent(QKeyEvent *e) override;

private:
	void setupStep();
	void refreshLang();
	void showFinished();
	void createLanguageLink();
	void checkUpdateStatus();
	void setupNextButton();
	void handleUpdates(const MTPUpdates &updates);
	void handleUpdate(const MTPUpdate &update);
	void backRequested();

	void updateControlsGeometry();
	[[nodiscard]] not_null<details::Data*> getData() {
		return &_data;
	}

	void fixOrder();
	void showControls();
	void hideControls();

	[[nodiscard]] details::Step *getStep(int skip = 0) const {
		Expects(skip >= 0);
		Expects(skip < _stepHistory.size());

		return _stepHistory[_stepHistory.size() - skip - 1];
	}
	void historyMove(details::StackAction action, details::Animate animate);
	void moveToStep(
		details::Step *step,
		details::StackAction action,
		details::Animate animate);
	void appendStep(details::Step *step);


	// FloatDelegate
	[[nodiscard]] auto floatPlayerDelegate()
		-> not_null<Media::Player::FloatDelegate*>;
	[[nodiscard]] auto floatPlayerSectionDelegate()
		-> not_null<Media::Player::FloatSectionDelegate*>;
	not_null<Ui::RpWidget*> floatPlayerWidget() override;
	void floatPlayerToggleGifsPaused(bool paused) override;
	not_null<Media::Player::FloatSectionDelegate*> floatPlayerGetSection(
		Window::Column column) override;
	void floatPlayerEnumerateSections(Fn<void(
		not_null<Media::Player::FloatSectionDelegate*> widget,
		Window::Column widgetColumn)> callback) override;
	bool floatPlayerIsVisible(not_null<HistoryItem*> item) override;
	void floatPlayerDoubleClickEvent(
		not_null<const HistoryItem*> item) override;

	// FloatSectionDelegate
	QRect floatPlayerAvailableRect() override;
	bool floatPlayerHandleWheelEvent(QEvent *e) override;

	const not_null<Main::Account*> _account;
	std::optional<MTP::Sender> _api;

	std::unique_ptr<Window::SlideAnimation> _showAnimation;

	std::vector<details::Step*> _stepHistory;
	rpl::lifetime _stepLifetime;

	details::Data _data;

	Ui::Animations::Simple _coverShownAnimation;
	int _nextTopFrom = 0;
	int _controlsTopFrom = 0;

	const style::RoundButton *_nextStyle = nullptr;

	object_ptr<Ui::FadeWrap<Ui::IconButton>> _back;
	object_ptr<Ui::FadeWrap<Ui::RoundButton>> _update = { nullptr };
	object_ptr<Ui::FadeWrap<Ui::RoundButton>> _settings;
	object_ptr<Ui::FadeWrap<Ui::FlatLabel>> _testModeLabel = { nullptr };

	object_ptr<Ui::FadeWrap<Ui::RoundButton>> _next;
	object_ptr<Ui::FadeWrap<Ui::LinkButton>> _changeLanguage = { nullptr };

	std::unique_ptr<Window::ConnectionState> _connecting;

	bool _backAvailable = false;
	bool _nextShown = true;
	Ui::Animations::Simple _nextShownAnimation;

};

} // namespace Intro
