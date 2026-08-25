/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_widget.h"

#include "intro/intro_step.h"
#include "intro/intro_start.h"
#include "intro/intro_server.h"
#include "lang/lang_keys.h"
#include "lang/lang_instance.h"
#include "lang/lang_cloud_manager.h"
#include "storage/localstorage.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "mainwindow.h"
#include "history/history.h"
#include "history/history_item.h"
#include "data/data_user.h"
#include "data/components/promo_suggestions.h"
#include "ui/text/text_utilities.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/labels.h"
#include "ui/wrap/fade_wrap.h"
#include "ui/ui_utility.h"
#include "boxes/abstract_box.h"
#include "ui/boxes/confirm_box.h"
#include "core/update_checker.h"
#include "core/application.h"
#include "mtproto/mtproto_dc_options.h"
#include "window/window_slide_animation.h"
#include "window/window_connecting_widget.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"
#include "window/section_widget.h"
#include "api/api_text_entities.h"
#include "styles/style_layers.h"
#include "styles/style_intro.h"
#include "base/qt/qt_common_adapters.h"

namespace Intro {
namespace {

using namespace ::Intro::details;

} // namespace

Widget::Widget(
	QWidget *parent,
	not_null<Window::Controller*> controller,
	not_null<Main::Account*> account,
	EnterPoint point,
	Main::Account *accountBeforeIntro)
: RpWidget(parent)
, _account(account)
, _data(details::Data{
	.controller = controller,
	.accountBeforeIntro = base::make_weak(accountBeforeIntro),
})
, _nextStyle(&st::introNextButton)
, _back(this, object_ptr<Ui::IconButton>(this, st::introBackButton))
, _settings(
	this,
	object_ptr<Ui::RoundButton>(
		this,
		tr::lng_menu_settings(),
		st::defaultBoxButton))
, _next(
	this,
	object_ptr<Ui::RoundButton>(this, nullptr, *_nextStyle))
, _connecting(std::make_unique<Window::ConnectionState>(
		this,
		account,
		rpl::single(true))) {
	_settings->entity()->setTextTransform(Ui::RoundButtonTextTransform::ToUpper);
	controller->setDefaultFloatPlayerDelegate(floatPlayerDelegate());

	_account->mtpValue(
	) | rpl::on_next([=](not_null<MTP::Instance*> instance) {
		_api.emplace(instance);
		crl::on_main(this, [=] { createLanguageLink(); });
	}, lifetime());

	switch (point) {
	case EnterPoint::Start:
		if (Core::App().domain().maybeLastOrSomeAuthedAccount()) {
			appendStep(new ServerWidget(this, _account, getData()));
		} else {
			appendStep(new StartWidget(this, _account, getData()));
		}
		break;
	default: Unexpected("Enter point in Intro::Widget::Widget.");
	}

	setupStep();
	fixOrder();

	if (_account->mtp().isTestMode()) {
		_testModeLabel.create(
			this,
			object_ptr<Ui::FlatLabel>(
				this,
				u"Test Mode"_q,
				st::defaultFlatLabel));
		_testModeLabel->entity()->setTextColorOverride(
			st::windowSubTextFg->c);
		_testModeLabel->show(anim::type::instant);
	}

	Lang::CurrentCloudManager().firstLanguageSuggestion(
	) | rpl::on_next([=] {
		createLanguageLink();
	}, lifetime());

	_account->mtpUpdates(
	) | rpl::on_next([=](const MTPUpdates &updates) {
		handleUpdates(updates);
	}, lifetime());

	// A pinned endpoint that failed on its face. The wording must not
	// send the user off to check their connection: a key mismatch in
	// particular can be something on the path answering for the
	// server, and retrying through it is the one wrong reaction.
	_account->mtp().pinnedServerFailure(
	) | rpl::on_next([=](
			std::optional<MTP::PinnedServerFailureReport> report) {
		if (!report) {
			return;
		}
		const auto text = (
			report->failure == MTP::PinnedServerFailure::KeyMismatch
		)	? tr::lng_intro_server_key_mismatch(tr::now)
		: tr::lng_intro_server_dc_mismatch(
			tr::now,
			lt_dc,
			QString::number(
				_account->mtp().dcOptions().customServer().dcId));
		getStep()->showError(rpl::single(text));
	}, lifetime());

	_back->entity()->setClickedCallback([=] { backRequested(); });
	_back->entity()->setAccessibleName(tr::lng_go_back(tr::now));
	_back->hide(anim::type::instant);

	if (_changeLanguage) {
		_changeLanguage->finishAnimating();
	}

	Lang::Updated(
	) | rpl::on_next([=] {
		refreshLang();
	}, lifetime());

	show();
	showControls();
	getStep()->showFast();
	setInnerFocus();

	if (!Core::UpdaterDisabled()) {
		Core::UpdateChecker checker;
		checker.start();
		rpl::merge(
			rpl::single(rpl::empty),
			checker.isLatest(),
			checker.failed(),
			checker.ready()
		) | rpl::on_next([=] {
			checkUpdateStatus();
		}, lifetime());
	}
}

rpl::producer<> Widget::showSettingsRequested() const {
	return _settings->entity()->clicks() | rpl::to_empty;
}

not_null<Media::Player::FloatDelegate*> Widget::floatPlayerDelegate() {
	return static_cast<Media::Player::FloatDelegate*>(this);
}

auto Widget::floatPlayerSectionDelegate()
-> not_null<Media::Player::FloatSectionDelegate*> {
	return static_cast<Media::Player::FloatSectionDelegate*>(this);
}

not_null<Ui::RpWidget*> Widget::floatPlayerWidget() {
	return this;
}

void Widget::floatPlayerToggleGifsPaused(bool paused) {
}

auto Widget::floatPlayerGetSection(Window::Column column)
-> not_null<Media::Player::FloatSectionDelegate*> {
	return this;
}

void Widget::floatPlayerEnumerateSections(Fn<void(
		not_null<Media::Player::FloatSectionDelegate*> widget,
		Window::Column widgetColumn)> callback) {
	callback(this, Window::Column::Second);
}

bool Widget::floatPlayerIsVisible(not_null<HistoryItem*> item) {
	return false;
}

void Widget::floatPlayerDoubleClickEvent(not_null<const HistoryItem*> item) {
	getData()->controller->invokeForSessionController(
		&item->history()->peer->session().account(),
		item->history()->peer,
		[&](not_null<Window::SessionController*> controller) {
			controller->showMessage(item);
		});
}

QRect Widget::floatPlayerAvailableRect() {
	return mapToGlobal(rect());
}

bool Widget::floatPlayerHandleWheelEvent(QEvent *e) {
	return false;
}

void Widget::refreshLang() {
	_changeLanguage.destroy();
	createLanguageLink();
	InvokeQueued(this, [this] { updateControlsGeometry(); });
}

void Widget::handleUpdates(const MTPUpdates &updates) {
	updates.match([&](const MTPDupdateShort &data) {
		handleUpdate(data.vupdate());
	}, [&](const MTPDupdates &data) {
		for (const auto &update : data.vupdates().v) {
			handleUpdate(update);
		}
	}, [&](const MTPDupdatesCombined &data) {
		for (const auto &update : data.vupdates().v) {
			handleUpdate(update);
		}
	}, [](const auto &) {});
}

void Widget::handleUpdate(const MTPUpdate &update) {
	update.match([&](const MTPDupdateDcOptions &data) {
		_account->mtp().dcOptions().addFromList(data.vdc_options());
	}, [&](const MTPDupdateConfig &data) {
		_account->mtp().requestConfig();
		if (_account->sessionExists()) {
			_account->session().promoSuggestions().invalidate();
		}
	}, [&](const MTPDupdateServiceNotification &data) {
		const auto text = TextWithEntities{
			qs(data.vmessage()),
			Api::EntitiesFromMTP(nullptr, data.ventities().v)
		};
		Ui::show(Ui::MakeInformBox(text));
	}, [](const auto &) {});
}

void Widget::createLanguageLink() {
	if (_changeLanguage
		|| Core::App().domain().maybeLastOrSomeAuthedAccount()) {
		return;
	}

	const auto createLink = [=](
			const QString &text,
			const QString &languageId) {
		_changeLanguage.create(
			this,
			object_ptr<Ui::LinkButton>(this, text));
		_changeLanguage->hide(anim::type::instant);
		_changeLanguage->entity()->setClickedCallback([=] {
			Lang::CurrentCloudManager().switchToLanguage(languageId);
		});
		_changeLanguage->toggle(
			_nextShown,
			anim::type::normal);
		updateControlsGeometry();
	};

	const auto currentId = Lang::LanguageIdOrDefault(Lang::Id());
	const auto defaultId = Lang::DefaultLanguageId();
	const auto suggested = Lang::CurrentCloudManager().suggestedLanguage();
	if (currentId != defaultId) {
		createLink(
			Lang::GetOriginalValue(tr::lng_switch_to_this.base),
			defaultId);
	} else if (!suggested.isEmpty() && suggested != currentId && _api) {
		_api->request(MTPlangpack_GetStrings(
			MTP_string(Lang::CloudLangPackName()),
			MTP_string(suggested),
			MTP_vector<MTPstring>(1, MTP_string("lng_switch_to_this"))
		)).done([=](const MTPVector<MTPLangPackString> &result) {
			const auto strings = Lang::Instance::ParseStrings(result);
			const auto i = strings.find(tr::lng_switch_to_this.base);
			if (i != strings.end()) {
				createLink(i->second, suggested);
			}
		}).send();
	}
}

void Widget::checkUpdateStatus() {
	Expects(!Core::UpdaterDisabled());

	if (Core::UpdateChecker().state() == Core::UpdateChecker::State::Ready) {
		if (_update) return;
		_update.create(
			this,
			object_ptr<Ui::RoundButton>(
				this,
				tr::lng_menu_update(),
				st::defaultBoxButton));
		_update->entity()->setTextTransform(Ui::RoundButtonTextTransform::ToUpper);
		if (!_showAnimation) {
			_update->setVisible(true);
		}
		const auto stepHasCover = getStep()->hasCover();
		_update->toggle(!stepHasCover, anim::type::instant);
		_update->entity()->setClickedCallback([] {
			Core::checkReadyUpdate();
			Core::Restart();
		});
	} else {
		if (!_update) return;
		_update.destroy();
	}
	updateControlsGeometry();
}

void Widget::setInnerFocus() {
	if (getStep()->animating()) {
		setFocus();
	} else {
		getStep()->setInnerFocus();
	}
}

void Widget::setupStep() {
	getStep()->nextButtonStyle(
	) | rpl::on_next([=](const style::RoundButton *st) {
		const auto nextStyle = st ? st : &st::introNextButton;
		if (_nextStyle != nextStyle) {
			_nextStyle = nextStyle;
			const auto wasShown = _next->toggled();
			_next.destroy();
			_next.create(
				this,
				object_ptr<Ui::RoundButton>(this, nullptr, *nextStyle));
			showControls();
			updateControlsGeometry();
			_next->toggle(wasShown, anim::type::instant);
		}
	}, getStep()->lifetime());

	getStep()->nextButtonFocusRequests() | rpl::on_next([=] {
		if (_next && !_next->isHidden()) {
			_next->entity()->setFocus(Qt::OtherFocusReason);
		}
	}, getStep()->lifetime());

	getStep()->backAvailable() | rpl::on_next([=](bool available) {
		_backAvailable = available;
		_back->toggle(available, anim::type::normal);
	}, getStep()->lifetime());

}

void Widget::historyMove(StackAction action, Animate animate) {
	Expects(_stepHistory.size() > 1);

	if (getStep()->animating()) {
		return;
	}

	auto wasStep = getStep((action == StackAction::Back) ? 0 : 1);
	if (action == StackAction::Back) {
		_stepHistory.pop_back();
		wasStep->cancelled();
	} else if (action == StackAction::Replace) {
		_stepHistory.erase(_stepHistory.end() - 2);
	}

	setupStep();

	getStep()->prepareShowAnimated(wasStep);
	if (wasStep->hasCover() != getStep()->hasCover()) {
		_nextTopFrom = wasStep->nextButtonTop();
		_controlsTopFrom = wasStep->hasCover() ? st::introCoverHeight : 0;
		_coverShownAnimation.start(
			[this] { updateControlsGeometry(); },
			0.,
			1.,
			st::introCoverDuration,
			wasStep->hasCover() ? anim::linear : anim::easeOutCirc);
	}

	_stepLifetime.destroy();
	if (action == StackAction::Forward || action == StackAction::Replace) {
		wasStep->finished();
	}
	if (action == StackAction::Back || action == StackAction::Replace) {
		delete base::take(wasStep);
	}

	auto stepHasCover = getStep()->hasCover();
	_settings->toggle(!stepHasCover, anim::type::normal);
	if (_testModeLabel) {
		_testModeLabel->toggle(!stepHasCover, anim::type::normal);
	}
	if (_update) {
		_update->toggle(!stepHasCover, anim::type::normal);
	}
	setupNextButton();
	getStep()->showAnimated(animate);
	fixOrder();
}

void Widget::fixOrder() {
	_next->raise();
	if (_update) _update->raise();
	if (_changeLanguage) _changeLanguage->raise();
	_settings->raise();
	_back->raise();
	floatPlayerRaiseAll();
	_connecting->raise();

	// Steps that name a first field get the field → Next → Back →
	// Settings tab chain; the rest keep the default order.
	if (auto first = getStep()->firstTabWidget()) {
		QWidget::setTabOrder(first, _next->entity());
		QWidget::setTabOrder(_next->entity(), _back->entity());
		QWidget::setTabOrder(_back->entity(), _settings->entity());
	}
}

void Widget::moveToStep(Step *step, StackAction action, Animate animate) {
	appendStep(step);
	_back->raise();
	_settings->raise();
	if (_update) {
		_update->raise();
	}
	_connecting->raise();

	historyMove(action, animate);
}

void Widget::appendStep(Step *step) {
	_stepHistory.push_back(step);
	step->setGeometry(rect());
	step->setGoCallback([=](Step *step, StackAction action, Animate animate) {
		if (action == StackAction::Back) {
			backRequested();
		} else {
			moveToStep(step, action, animate);
		}
	});
	step->setStepBelowCallback([=]() -> Step* {
		return (_stepHistory.size() > 1) ? getStep(1) : nullptr;
	});
}

void Widget::showControls() {
	getStep()->show();
	setupNextButton();
	_next->toggle(_nextShown, anim::type::instant);
	_nextShownAnimation.stop();
	_connecting->setForceHidden(false);
	auto hasCover = getStep()->hasCover();
	_settings->toggle(!hasCover, anim::type::instant);
	if (_testModeLabel) {
		_testModeLabel->toggle(!hasCover, anim::type::instant);
	}
	if (_update) {
		_update->toggle(!hasCover, anim::type::instant);
	}
	if (_changeLanguage) {
		_changeLanguage->toggle(
			_nextShown,
			anim::type::instant);
	}
	_back->toggle(_backAvailable, anim::type::instant);
}

void Widget::setupNextButton() {
	_next->entity()->setClickedCallback([=] { getStep()->submit(); });

	_next->entity()->setText(getStep()->nextButtonText(
	) | rpl::filter([](const QString &text) {
		return !text.isEmpty();
	}));
	getStep()->nextButtonText(
	) | rpl::map([](const QString &text) {
		return !text.isEmpty();
	}) | rpl::filter([=](bool visible) {
		return visible != _nextShown;
	}) | rpl::on_next([=](bool visible) {
		_next->toggle(visible, anim::type::normal);
		_nextShown = visible;
		if (_changeLanguage) {
			_changeLanguage->toggle(
				_nextShown,
				anim::type::normal);
		}
		_nextShownAnimation.start(
			[=] { updateControlsGeometry(); },
			_nextShown ? 0. : 1.,
			_nextShown ? 1. : 0.,
			st::slideDuration);
	}, _stepLifetime);
}

void Widget::hideControls() {
	getStep()->hide();
	_next->hide(anim::type::instant);
	_connecting->setForceHidden(true);
	_settings->hide(anim::type::instant);
	if (_testModeLabel) _testModeLabel->hide(anim::type::instant);
	if (_update) _update->hide(anim::type::instant);
	if (_changeLanguage) _changeLanguage->hide(anim::type::instant);
	_back->hide(anim::type::instant);
}

void Widget::showAnimated(QPixmap oldContentCache, bool back) {
	_showAnimation = nullptr;

	showControls();
	floatPlayerHideAll();
	auto newContentCache = Ui::GrabWidget(this);
	hideControls();
	floatPlayerShowVisible();

	_showAnimation = std::make_unique<Window::SlideAnimation>();
	_showAnimation->setDirection(back
		? Window::SlideDirection::FromLeft
		: Window::SlideDirection::FromRight);
	_showAnimation->setRepaintCallback([=] { update(); });
	_showAnimation->setFinishedCallback([=] { showFinished(); });
	_showAnimation->setPixmaps(oldContentCache, newContentCache);
	_showAnimation->start();

	show();
}

void Widget::showFinished() {
	_showAnimation = nullptr;

	showControls();
	getStep()->activate();
}

void Widget::paintEvent(QPaintEvent *e) {
	const auto trivial = (rect() == e->rect());
	setMouseTracking(true);

	QPainter p(this);
	if (!trivial) {
		p.setClipRect(e->rect());
	}
	if (_showAnimation) {
		_showAnimation->paintContents(p);
		return;
	}
	p.fillRect(e->rect(), st::windowBg);
}

void Widget::resizeEvent(QResizeEvent *e) {
	if (_stepHistory.empty()) {
		return;
	}
	for (const auto step : _stepHistory) {
		step->setGeometry(rect());
	}

	updateControlsGeometry();
	floatPlayerAreaUpdated();
}

void Widget::updateControlsGeometry() {
	const auto skip = st::introSettingsSkip;
	const auto shown = _coverShownAnimation.value(1.);

	const auto controlsTop = anim::interpolate(
		_controlsTopFrom,
		getStep()->hasCover() ? st::introCoverHeight : 0,
		shown);
	_settings->moveToRight(skip, controlsTop + skip);
	if (_testModeLabel) {
		_testModeLabel->moveToRight(
			skip + _settings->width() + skip,
			_settings->y()
				+ (_settings->height()
				- _testModeLabel->height()) / 2);
	}
	if (_update) {
		_update->moveToRight(
			skip + _settings->width() + skip,
			_settings->y());
	}
	_back->moveToLeft(0, controlsTop);

	auto nextTopTo = getStep()->nextButtonTop();
	auto nextTop = anim::interpolate(_nextTopFrom, nextTopTo, shown);
	const auto shownAmount = _nextShownAnimation.value(_nextShown ? 1. : 0.);
	const auto realNextTop = anim::interpolate(
		nextTop + st::introNextSlide,
		nextTop,
		shownAmount);
	_next->moveToLeft((width() - _next->width()) / 2, realNextTop);
	getStep()->setShowAnimationClipping(shownAmount > 0
		? QRect(0, 0, width(), realNextTop)
		: QRect());
	if (_changeLanguage) {
		_changeLanguage->moveToLeft(
			(width() - _changeLanguage->width()) / 2,
			_next->y() + _next->height() + _changeLanguage->height());
	}
}

void Widget::keyPressEvent(QKeyEvent *e) {
	if (_showAnimation || getStep()->animating()) return;

	if (e->key() == Qt::Key_Escape || e->key() == Qt::Key_Back) {
		if (_backAvailable) {
			backRequested();
		}
	} else if (e->key() == Qt::Key_Enter
		|| e->key() == Qt::Key_Return
		|| e->key() == Qt::Key_Space) {
		getStep()->submit();
	}
}

void Widget::backRequested() {
	const auto back = getData()->accountBeforeIntro.get();
	if (_stepHistory.size() > 1) {
		historyMove(StackAction::Back, Animate::Back);
	} else if (back && back->sessionExists()) {
		Core::App().setActivePrimaryWindow(getData()->controller);
		back->domain().activate(back);
	} else if (const auto parent
		= Core::App().domain().maybeLastOrSomeAuthedAccount()) {
		Core::App().domain().activate(parent);
	} else {
		moveToStep(
			Ui::CreateChild<StartWidget>(this, _account, getData()),
			StackAction::Replace,
			Animate::Back);
	}
}

Widget::~Widget() {
	for (auto step : base::take(_stepHistory)) {
		delete step;
	}
}

} // namespace Intro
