/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_server.h"

#include "intro/intro_widget.h"
#include "intro/intro_phone.h"
#include "lang/lang_keys.h"
#include "main/main_account.h"
#include "mtproto/mtproto_dc_options.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "ui/rp_widget.h"
#include "ui/ui_utility.h"
#include "window/window_controller.h"
#include "styles/style_intro.h"

#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>
#include <QtGui/QPainter>
#include <QtGui/QFontMetrics>

namespace Intro {
namespace details {
namespace {

[[nodiscard]] QString ExtractKeyId(const QString &text) {
	const auto needle = u"key_id="_q;
	const auto pos = text.indexOf(needle);
	if (pos < 0) {
		return text.trimmed();
	}
	const auto start = pos + needle.size();
	auto end = start;
	while (end < text.size() && !text[end].isSpace()) {
		++end;
	}
	return text.mid(start, end - start);
}

} // namespace

ServerWidget::ServerWidget(
	QWidget *parent,
	not_null<Main::Account*> account,
	not_null<Data*> data)
: Step(parent, account, data)
, _address(
	this,
	st::introCountry,
	tr::lng_intro_server_address_ph())
, _key(
	this,
	st::introServerKeyField,
	tr::lng_intro_server_key_ph(),
	QString(),
	Ui::InputField::Mode::MultiLine) {
	_locked = account->sessionExists();

	setTitleText(tr::lng_intro_server_title());
	setDescriptionText(tr::lng_intro_server_desc());

	if (_locked) {
		_address->setReadOnly(true);
		_key->setReadOnly(true);
		showError(rpl::single(tr::lng_intro_server_locked(tr::now)));
	}

	_address->setAccessibleName(
		tr::lng_intro_server_address_ph(tr::now));
	_key->setAccessibleName(
		tr::lng_intro_server_key_ph(tr::now));
	_address->setMaxLength(120);

	const auto onChanged = [=] { hideError(); };
	connect(_address, &Ui::InputField::changed, onChanged);
	connect(_key, &Ui::InputField::changed, onChanged);

	if (account->mtp().dcOptions().hasCustomServer()) {
		const auto cs = account->mtp().dcOptions().customServer();
		_address->setText(QString::fromStdString(cs.ip)
			+ u":"_q
			+ QString::number(cs.port));
	}
	if (!getData()->serverAddress.isEmpty()) {
		_address->setText(getData()->serverAddress);
	}
	if (!getData()->serverPem.isEmpty()) {
		_key->setText(getData()->serverPem);
	}
}

int ServerWidget::nextButtonTop() const {
	return contentTop() + st::introServerNextTop;
}

int ServerWidget::errorTop() const {
	return contentTop() + st::introServerErrorTop;
}

void ServerWidget::setInnerFocus() {
	_address->setFocusFast();
}

void ServerWidget::activate() {
	Step::activate();
	_address->setFocusFast();
}

void ServerWidget::resizeEvent(QResizeEvent *e) {
	Step::resizeEvent(e);
	_address->moveToLeft(contentLeft(), contentTop() + 100);
	_key->moveToLeft(contentLeft(), contentTop() + 167);
}

void ServerWidget::submit() {
	const auto addressText = _address->getLastText();
	const auto keyText = _key->getLastText();

	const auto endpointCheck = MTP::CheckServerEndpoint(addressText);
	if (!endpointCheck) {
		QString msg;
		switch (endpointCheck.status) {
		case MTP::ServerEndpointStatus::Empty:
			msg = tr::lng_intro_server_address_empty(tr::now);
			break;
		case MTP::ServerEndpointStatus::NoPort:
			msg = tr::lng_intro_server_address_no_port(tr::now);
			break;
		case MTP::ServerEndpointStatus::BadPort:
			msg = tr::lng_intro_server_address_bad_port(tr::now);
			break;
		default:
			msg = tr::lng_intro_server_address_invalid(tr::now);
			break;
		}
		_address->showError();
		showError(rpl::single(msg));
		return;
	}

	const auto keyCheck = MTP::CheckServerKey(keyText);
	if (!keyCheck) {
		QString msg;
		switch (keyCheck.status) {
		case MTP::ServerKeyStatus::Empty:
			msg = tr::lng_intro_server_key_empty(tr::now);
			break;
		case MTP::ServerKeyStatus::PrivateKey:
			msg = tr::lng_intro_server_key_private(tr::now);
			break;
		case MTP::ServerKeyStatus::NotRsaKey:
			msg = tr::lng_intro_server_key_not_rsa(tr::now);
			break;
		case MTP::ServerKeyStatus::BadModulusSize:
			msg = tr::lng_intro_server_key_bits(
				tr::now,
				lt_bits,
				QString::number(keyCheck.modulusBits));
			break;
		case MTP::ServerKeyStatus::InternalError:
			msg = tr::lng_intro_server_key_internal(tr::now);
			break;
		default:
			msg = tr::lng_intro_server_key_invalid(tr::now);
			break;
		}
		_key->showError();
		showError(rpl::single(msg));
		return;
	}

	getData()->serverAddress = addressText;
	getData()->serverPem = keyText;
	goNext<ServerKeyWidget>();
}

ServerKeyWidget::ServerKeyWidget(
	QWidget *parent,
	not_null<Main::Account*> account,
	not_null<Data*> data)
: Step(parent, account, data)
, _panel(this)
, _compare(
	_panel,
	st::introServerCompareField,
	tr::lng_intro_server_check_ph())
, _copy(
	_panel,
	tr::lng_intro_server_check_copy(tr::now)) {
	setTitleText(tr::lng_intro_server_check_title());
	setDescriptionText(tr::lng_intro_server_check_desc());

	_endpoint = MTP::CheckServerEndpoint(getData()->serverAddress);
	_keyCheck = MTP::CheckServerKey(getData()->serverPem);

	if (_keyCheck.valid()) {
		const auto identity = _keyCheck.identity;
		const auto groupsString = [&] {
			auto result = QString();
			auto charInGroup = 0;
			for (const auto ch : identity) {
				if (ch == QChar::fromLatin1('-')) {
					result += u", "_q;
					charInGroup = 0;
				} else {
					if (charInGroup > 0) {
						result += QChar::fromLatin1(' ');
					}
					result += ch;
					++charInGroup;
				}
			}
			return result;
		}();
		_panel->setAccessibleName(
			tr::lng_intro_server_check_value_a11y(
				tr::now,
				lt_groups,
				groupsString));
	}

	_compare->setAccessibleName(
		tr::lng_intro_server_check_ph(tr::now));

	_panel->paintRequest(
	) | rpl::on_next([=](QRect clip) {
		auto p = QPainter(_panel.data());
		paintPanel(p);
	}, _panel->lifetime());

	connect(_compare, &Ui::InputField::changed, [=] {
		updateVerdict();
	});

	_copy->setClickedCallback([=] {
		if (_keyCheck.valid()) {
			QGuiApplication::clipboard()->setText(_keyCheck.identity);
			getData()->controller->showToast(
				tr::lng_text_copied(tr::now));
		}
	});
}

int ServerKeyWidget::nextButtonTop() const {
	return contentTop() + st::introServerNextTop;
}

void ServerKeyWidget::activate() {
	Step::activate();
	_panel->show();
	_compare->setFocusFast();
}

void ServerKeyWidget::resizeEvent(QResizeEvent *e) {
	Step::resizeEvent(e);

	const auto panelW = st::introServerPanelWidth;
	const auto panelX = (width() - panelW) / 2;
	const auto panelY = contentTop() + 120;

	const auto panelH = 170;
	_panel->setGeometry(panelX, panelY, panelW, panelH);

	const auto compareX = (panelW - st::introServerCompareField.width) / 2;
	_compare->moveToLeft(compareX, 65);

	const auto copyWidth = _copy->width();
	_copy->moveToLeft(panelW - copyWidth - 8, 140);
}

void ServerKeyWidget::paintEvent(QPaintEvent *e) {
	Step::paintEvent(e);
}

void ServerKeyWidget::paintPanel(QPainter &p) {
	const auto r = QRect(0, 0, _panel->width(), _panel->height());

	p.setRenderHint(QPainter::Antialiasing);

	p.setPen(Qt::NoPen);
	p.setBrush(st::introServerPanelBg->b);
	const auto radius = st::introServerPanelRadius;
	p.drawRoundedRect(r, radius, radius);

	if (!_keyCheck.valid()) {
		return;
	}

	const auto identity = _keyCheck.identity;
	constexpr auto kGroupCount = 16;
	constexpr auto kGroupSize = 4;
	constexpr auto kHalfGroups = kGroupCount / 2;
	constexpr auto kRow1Len = kHalfGroups * kGroupSize + (kHalfGroups - 1);
	const auto row1 = identity.left(kRow1Len) + u"-"_q;
	const auto row2 = identity.mid(kRow1Len + 1);

	p.setFont(st::introServerIdentityFont);
	p.setPen(st::windowFg->c);

	const auto textX = 8;
	p.drawText(textX, 8 + QFontMetrics(st::introServerIdentityFont).ascent(), row1);
	p.drawText(textX, 28 + QFontMetrics(st::introServerIdentityFont).ascent(), row2);

	p.setPen(st::shadowFg->c);
	p.drawLine(8, 56, _panel->width() - 8, 56);

	const auto verdictY = 140 + QFontMetrics(st::introServerIdentityFont).ascent();
	switch (_verdict) {
	case Verdict::None:
		p.setPen(st::windowSubTextFg->c);
		p.drawText(8, verdictY, tr::lng_intro_server_check_none(tr::now));
		break;
	case Verdict::Match:
		p.setPen(st::activeLineFg->c);
		p.drawText(8, verdictY, tr::lng_intro_server_check_match(tr::now));
		break;
	case Verdict::Mismatch:
		p.setPen(st::boxTextFgError->c);
		p.drawText(8, verdictY, tr::lng_intro_server_check_mismatch(tr::now));
		break;
	}
}

void ServerKeyWidget::updateVerdict() {
	const auto typed = ExtractKeyId(_compare->getLastText());
	if (typed.isEmpty()) {
		_verdict = Verdict::None;
	} else if (_keyCheck.valid()
		&& MTP::ServerKeyIdentityMatches(typed, _keyCheck.identity)) {
		_verdict = Verdict::Match;
	} else {
		_verdict = Verdict::Mismatch;
	}
	_panel->update();
}

void ServerKeyWidget::commitAndAdvance() {
	if (!_endpoint || !_keyCheck) {
		return;
	}
	const auto key = std::make_shared<MTP::details::RSAPublicKey>(
		_keyCheck.key);
	account().mtp().dcOptions().setCustomServer(MTP::CustomServer{
		.dcId = 2,
		.ip = _endpoint.host,
		.port = _endpoint.port,
		.key = key,
	});
	account().mtp().restart();
	goNext<PhoneWidget>();
}

void ServerKeyWidget::submit() {
	if (_verdict == Verdict::Mismatch) {
		return; // mismatch is a hard block; clear the field to continue
	}
	commitAndAdvance();
}

} // namespace details
} // namespace Intro
