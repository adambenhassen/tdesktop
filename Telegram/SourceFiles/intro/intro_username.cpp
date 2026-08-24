/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_username.h"

#include "config.h"
#include "intro/intro_password_check.h"
#include "intro/intro_username_validation.h"
#include "intro/intro_widget.h"
#include "lang/lang_keys.h"
#include "main/main_account.h"
#include "main/main_domain.h"
#include "main/main_session.h"
#include "data/data_user.h"
#include "core/application.h"
#include "core/core_cloud_password.h"
#include "mtproto/mtproto_dc_options.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/facade.h" // MTP::RequestSent
#include "base/bytes.h"
#include "base/qt/qt_string_view.h" // base::StringViewMid
#include "ui/text/format_values.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "base/random.h"
#include "base/timer.h"
#include "styles/style_intro.h"

#include <QtGui/QAccessible>
#include <QtWidgets/QTextEdit>

namespace Intro {
namespace details {
namespace {

constexpr auto kStillWaitingAfterSeconds = 10;

[[nodiscard]] qint64 NowMs() {
	return crl::now();
}

[[nodiscard]] int FloodWaitSeconds(const MTP::Error &error) {
	return base::StringViewMid(
		error.type(),
		u"FLOOD_WAIT_"_q.size()).toInt();
}

} // namespace

UsernameWidget::UsernameWidget(
	QWidget *parent,
	not_null<Main::Account*> account,
	not_null<Data*> data)
: Step(parent, account, data)
, _username(
	this,
	st::introName,
	tr::lng_intro_username_ph())
, _checkRequestTimer([=] { checkRequest(); }) {
	_username->setAccessibleName(tr::lng_intro_username_ph(tr::now));

	setTitleText(tr::lng_intro_username_title());
	setDescriptionText(tr::lng_intro_username_desc(
		tr::now,
		lt_server,
		getData()->serverAddress));
	setErrorCentered(false);

	_username->changes() | rpl::on_next([=] {
		usernameChanged();
	}, _username->lifetime());

	_username->submits() | rpl::on_next([=](Qt::KeyboardModifiers) {
		submit();
	}, _username->lifetime());
}

int UsernameWidget::nextButtonTop() const {
	return contentTop() + st::introServerNextTop;
}

int UsernameWidget::errorTop() const {
	return contentTop() + st::introUsernameErrorTop;
}

void UsernameWidget::setInnerFocus() {
	_username->setFocusFast();
}

void UsernameWidget::activate() {
	Step::activate();
	_username->setFocusFast();
}

void UsernameWidget::resizeEvent(QResizeEvent *e) {
	Step::resizeEvent(e);
	_username->moveToLeft(contentLeft(), contentTop() + st::introStepFieldTop);
	if (_status) {
		_status->moveToLeft(
			contentLeft() + st::buttonRadius,
			errorTop());
	}
}

QWidget *UsernameWidget::firstTabWidget() const {
	return _username.data();
}

void UsernameWidget::usernameChanged() {
	hideError();
	describeState(QString());
}

void UsernameWidget::fail(const QString &text) {
	stopPending();
	_username->showError();
	showError(rpl::single(text));
	describeState(text);
}

// The inline state of this step lives in the line below the field, so
// both the step and the field carry it: a reader that announces role
// plus name plus description reaches it only through the field.
void UsernameWidget::describeState(const QString &text) {
	setAccessibleDescription(text);
	_username->setAccessibleDescription(text);
}

void UsernameWidget::startPending() {
	if (_pending.current()) {
		return;
	}
	_pending = true;
	_waitingSeconds = 0;
	_escalated = false;
	_reissuedOnce = false;
	hideError();
	describeState(QString());
	// Read-only, not disabled: a disabled field loses its accessible
	// text on some platforms.
	_username->rawTextEdit()->setReadOnly(true);
	showStatus(tr::lng_intro_checking(tr::now));
	_checkRequestTimer.callEach(1000);
}

void UsernameWidget::stopPending() {
	if (!_pending.current()) {
		return;
	}
	_pending = false;
	_checkRequestTimer.cancel();
	_username->rawTextEdit()->setReadOnly(false);
	hideStatus();
}

void UsernameWidget::showStatus(const QString &text) {
	if (!_status) {
		_status.create(this, QString(), st::introDescription);
		_status->setTextColorOverride(st::windowSubTextFg->c);
		_status->resizeToWidth(st::introDescription.minWidth);
		_status->moveToLeft(contentLeft() + st::buttonRadius, errorTop());
	}
	_status->setText(text);
	_status->show();
	describeState(text);
	announceStatus();
}

void UsernameWidget::hideStatus() {
	if (_status) {
		_status->hide();
	}
}

void UsernameWidget::announceStatus() {
	QAccessibleEvent alertEvent(this, QAccessible::Alert);
	QAccessible::updateAccessibility(&alertEvent);
}

void UsernameWidget::checkRequest() {
	auto status = api().instance().state(_sentRequest);
	if (!_sentRequest && status == MTP::RequestSent) {
		_checkRequestTimer.cancel();
		return;
	}
	if (++_waitingSeconds >= kStillWaitingAfterSeconds && !_escalated) {
		_escalated = true;
		// Not a terminal error and not a cancellation: MTProto queues
		// requests until the transport comes up, so "unreachable" is
		// something only the server can disprove. A negative state here
		// is a transport-side wait, not an answer — the request stays
		// alive and only the wording escalates.
		showStatus(tr::lng_intro_still_waiting(
			tr::now,
			lt_server,
			getData()->serverAddress));
	}
}

rpl::producer<QString> UsernameWidget::nextButtonText() const {
	return _pending.value(
	) | rpl::map([](bool pending) {
		return pending
			? tr::lng_intro_please_wait(tr::now)
			: tr::lng_intro_next(tr::now);
	});
}

void UsernameWidget::submit() {
	if (_pending.current()) {
		return;
	}

	const auto normalized = NormalizeUsernameInput(_username->getLastText());
	if (normalized.isEmpty()) {
		fail(tr::lng_intro_username_empty(tr::now));
		return;
	} else if (!IsValidUsername(normalized)) {
		fail(tr::lng_intro_username_bad(tr::now));
		return;
	}

	const auto wire = ToWireUsername(normalized);

	// An existing local account with the same username on the same
	// server pair is that user already — activate it instead of making
	// them prove it again over the network.
	const auto &mine = account().mtp().dcOptions().customServer();
	for (const auto &[index, existing] : Core::App().domain().accounts()) {
		const auto raw = existing.get();
		if (!raw->maybeSession()) {
			continue;
		} else if (raw->mtp().environment() != account().mtp().environment()) {
			continue;
		} else if (!raw->session().user()
			|| wire.compare(
				raw->session().user()->username(),
				Qt::CaseInsensitive) != 0) {
			continue;
		}
		const auto &theirs = raw->mtp().dcOptions().customServer();
		if (mine.empty()
			|| theirs.empty()
			|| mine.ip != theirs.ip
			|| mine.port != theirs.port
			|| !mine.key
			|| !theirs.key
			|| mine.key->fingerprint() != theirs.key->fingerprint()) {
			continue;
		}
		crl::on_main(raw, [=] {
			Core::App().domain().activate(raw);
		});
		return;
	}

	startPending();
	_sentUsername = wire;

	auto &cache = getData()->usernameCode;
	if (cache.freshFor(_sentUsername, NowMs())) {
		_sentHash = cache.hash;
		signIn();
	} else {
		cache.drop();
		requestCode();
	}
}

void UsernameWidget::requestCode() {
	_sentRequest = api().request(MTPauth_SendCode(
		MTP_string(_sentUsername),
		MTP_int(ApiId),
		MTP_string(ApiHash),
		MTP_codeSettings(
			MTP_flags(0),
			MTPVector<MTPbytes>(),
			MTPstring(),
			MTPBool())
	)).done([=](const MTPauth_SentCode &result) {
		_sentRequest = 0;
		sendCodeDone(result);
	}).fail([=](const MTP::Error &error) {
		_sentRequest = 0;
		requestFail(error);
	}).handleAllErrors().send();
}

void UsernameWidget::signIn() {
	_sentRequest = api().request(MTPauth_SignIn(
		MTP_flags(0),
		MTP_string(_sentUsername),
		MTP_bytes(_sentHash),
		MTP_string(QString()), // phone_code: ignored in username mode.
		MTP_emailVerificationCode(MTP_string(QString()))
	)).done([=](const MTPauth_Authorization &result) {
		_sentRequest = 0;
		signInDone(result);
	}).fail([=](const MTP::Error &error) {
		_sentRequest = 0;
		signInFail(error);
	}).handleAllErrors().send();
}

void UsernameWidget::sendCodeDone(const MTPauth_SentCode &result) {
	result.match([&](const MTPDauth_sentCode &data) {
		const auto hash = qba(data.vphone_code_hash());
		if (hash.isEmpty()) {
			LOG(("API Error: auth.sentCode without a phone_code_hash "
				"(UsernameWidget::sendCodeDone)."));
			fail(Lang::Hard::ServerError());
			return;
		}
		getData()->usernameCode = { _sentUsername, hash, NowMs() };
		_sentHash = hash;
		signIn();
	}, [&](const MTPDauth_sentCodeSuccess &data) {
		LOG(("Intro Username Warning: auth.sentCodeSuccess from sendCode; "
			"accepting the authorization."));
		getData()->phone = _sentUsername;
		getData()->phoneHash = _sentHash;
		finish(data.vauthorization());
	}, [&](const MTPDauth_sentCodePaymentRequired &) {
		LOG(("API Error: Unexpected auth.sentCodePaymentRequired "
			"(UsernameWidget::sendCodeDone)."));
		fail(tr::lng_intro_server_error(tr::now));
	});
}

void UsernameWidget::requestFail(const MTP::Error &error) {
	LOG(("Intro Username Error: sendCode failed with %1 (%2)"
		).arg(error.type()).arg(error.code()));
	if (MTP::IsFloodError(error)) {
		fail(tr::lng_intro_username_flood(
			tr::now,
			lt_duration,
			Ui::FormatDurationWords(FloodWaitSeconds(error))));
	} else if (error.type() == u"PHONE_NUMBER_INVALID"_q) {
		fail(tr::lng_intro_username_unavailable(tr::now));
	} else {
		fail(tr::lng_intro_server_error(tr::now));
	}
}

void UsernameWidget::signInDone(const MTPauth_Authorization &result) {
	result.match([&](const MTPDauth_authorization &data) {
		LOG(("Intro Username Warning: auth.authorization without a password "
			"step; accepting it."));
		carryForwardAndFinish(result);
	}, [&](const MTPDauth_authorizationSignUpRequired &data) {
		carryForwardAndFinish(result);
	});
}

// The username and its hash travel in Data's phone fields so the stock
// signup screen sends auth.signUp with the right identity unchanged.
// The password step gets its SRP challenge through pwdState instead.
void UsernameWidget::carryForwardAndFinish(
		const MTPauth_Authorization &result) {
	getData()->phone = _sentUsername;
	getData()->phoneHash = _sentHash;
	finish(result);
}

void UsernameWidget::signInFail(const MTP::Error &error) {
	const auto &type = error.type();
	if (type == u"SESSION_PASSWORD_NEEDED"_q) {
		passwordNeeded();
	} else if (type == u"PHONE_NUMBER_INVALID"_q) {
		LOG(("Intro Username Error: signIn failed with %1."
			).arg(type));
		fail(tr::lng_intro_username_unavailable(tr::now));
	} else if (type == u"PHONE_CODE_INVALID"_q
		|| type == u"PHONE_CODE_EXPIRED"_q) {
		reissueAndRetry();
	} else if (MTP::IsFloodError(error)) {
		fail(tr::lng_intro_username_flood(
			tr::now,
			lt_duration,
			Ui::FormatDurationWords(FloodWaitSeconds(error))));
	} else {
		LOG(("Intro Username Error: signIn failed with %1 (%2)"
			).arg(type).arg(error.code()));
		fail(tr::lng_intro_server_error(tr::now));
	}
}

void UsernameWidget::reissueAndRetry() {
	if (_reissuedOnce) {
		fail(tr::lng_intro_retry(tr::now));
		return;
	}
	_reissuedOnce = true;
	getData()->usernameCode.drop();
	_sentHash.clear();
	// Still pending from the submit that got us here.
	requestCode();
}

void UsernameWidget::passwordNeeded() {
	// Through _sentRequest like the other two round trips: the pending
	// timer watches it, and Back through cancelled() cancels it instead
	// of leaving a callback that would navigate a deleted step.
	_sentRequest = api().request(MTPaccount_GetPassword(
	)).done([=](const MTPaccount_Password &result) {
		_sentRequest = 0;
		result.match([&](const MTPDaccount_password &data) {
			base::RandomAddSeed(bytes::make_span(data.vsecure_random().v));
			getData()->pwdState = Core::ParseCloudPasswordState(data);
			const auto &request = getData()->pwdState.mtp.request;
			if (!getData()->pwdState.hasPassword || !request || !request.id
				|| request.B.empty()) {
				LOG(("Intro Username Error: getPassword returned no usable "
					"SRP challenge."));
				fail(tr::lng_intro_retry(tr::now));
				return;
			}
			goNext<PasswordCheckWidget>();
		});
	}).fail([=](const MTP::Error &error) {
		_sentRequest = 0;
		LOG(("Intro Username Error: getPassword failed with %1 (%2)"
			).arg(error.type()).arg(error.code()));
		fail(tr::lng_intro_server_error(tr::now));
	}).handleAllErrors().send();
}

void UsernameWidget::finished() {
	// Leaving forward while a request is in flight: this instance comes
	// back to life if the user presses Back on the next step, so the
	// pending state cannot survive the trip.
	stopPending();
	Step::finished();
	_checkRequestTimer.cancel();
	apiClear();

	cancelled();
}

void UsernameWidget::cancelled() {
	api().request(base::take(_sentRequest)).cancel();
}

} // namespace details
} // namespace Intro
