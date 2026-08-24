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

#include <QtGui/QAccessible>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>
#include <QtGui/QPainter>
#include <QtGui/QFontDatabase>
#include <QtGui/QFontMetrics>
#include <QtWidgets/QTextEdit>

namespace Intro {
namespace details {
namespace {

// Paints the two-row identity display into p at the standard position.
// Returns true when the rows were drawn; returns false when neither
// 13px nor 12px fits in the panel's inner width, in which case the
// caller should show a short fallback message instead.
[[nodiscard]] bool PaintIdentityRows(
		QPainter &p,
		const QString &identity,
		int panelWidth) {
	constexpr auto kRow1Len = 8 * 4 + 7; // 39 chars: 8 groups of 4 + 7 dashes
	const auto textX = 8;
	const auto innerWidth = panelWidth - textX * 2;
	const auto row1 = identity.left(kRow1Len) + u"-"_q;
	const auto row2 = identity.mid(kRow1Len + 1);

	auto monoFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
	monoFont.setPixelSize(13);
	const auto fm13 = QFontMetrics(monoFont);
	const auto adv13 = std::max(
		fm13.horizontalAdvance(row1),
		fm13.horizontalAdvance(row2));
	monoFont.setPixelSize(12);
	const auto fm12 = QFontMetrics(monoFont);
	const auto adv12 = std::max(
		fm12.horizontalAdvance(row1),
		fm12.horizontalAdvance(row2));

	const auto layout = MTP::ChooseIdentityLayout(innerWidth, adv13, adv12);
	if (!layout.fits) {
		return false;
	}

	monoFont.setPixelSize(layout.pixelSize);
	const auto fm = QFontMetrics(monoFont);
	p.setFont(monoFont);
	p.setPen(st::windowFg->c);
	p.drawText(textX, 8 + fm.ascent(), row1);
	p.drawText(textX, 28 + fm.ascent(), row2);
	return true;
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
	Ui::InputField::Mode::MultiLine,
	tr::lng_intro_server_key_ph()) {
	// This screen is never reached while the account holds readable local
	// data from another server. Two invariants protect it:
	//
	// 1. The intro is only shown when the mtp blob carries user id 0.
	//    setMtpAuthorization (main_account.cpp:510) sets _sessionUserId
	//    before reading any key; startMtp creates the session from it
	//    alone at :605. An account whose blob still names a user restores
	//    a session and bypasses the intro entirely.
	//    Break shape: zeroing the user id inside resetAuthorizationKeys()
	//    before its write (main_account.cpp:745) would let a kill during
	//    forcedLogOut() reach this screen with peer ids still cached.
	//
	// 2. Storage::Account::reset() zeroes every FileKey and flushes the
	//    map before handing file removal to crl::async
	//    (storage_account.cpp:821-824). An interrupted wipe leaves
	//    orphaned ciphertext and a blob naming user id 0 — not readable
	//    data — so invariant 1 prevents the intro from being reached.
	//    Break shape: reordering reset() to delete files before writeMap()
	//    would leave readable data behind an invalidated map.
	setTitleText(tr::lng_intro_server_title());
	setDescriptionText(tr::lng_intro_server_desc());

	_address->setAccessibleName(
		tr::lng_intro_server_address_ph(tr::now));
	_key->setAccessibleName(
		tr::lng_intro_server_key_ph(tr::now));
	_address->setMaxLength(120);

	const auto onChanged = [=] {
		hideError();
		setAccessibleDescription(QString());
	};
	_address->changes() | rpl::on_next(onChanged, _address->lifetime());
	_key->changes() | rpl::on_next(onChanged, _key->lifetime());

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
		case MTP::ServerEndpointStatus::EmptyHost:
			msg = tr::lng_intro_server_address_empty_host(tr::now);
			break;
		case MTP::ServerEndpointStatus::BadHost:
			msg = tr::lng_intro_server_address_bad_host(tr::now);
			break;
		case MTP::ServerEndpointStatus::HostTooLong:
			msg = tr::lng_intro_server_address_too_long(tr::now);
			break;
		case MTP::ServerEndpointStatus::UnbracketedIPv6:
			msg = tr::lng_intro_server_address_ipv6(tr::now);
			break;
		default:
			msg = tr::lng_intro_server_address_invalid(tr::now);
			break;
		}
		_address->showError();
		showError(rpl::single(msg));
		setAccessibleDescription(msg);
		QAccessibleEvent alertEvent(this, QAccessible::Alert);
		QAccessible::updateAccessibility(&alertEvent);
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
			_key->setText(QString());
			_key->rawTextEdit()->document()->clearUndoRedoStacks();
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
		case MTP::ServerKeyStatus::Unreadable:
			msg = tr::lng_intro_server_key_unreadable(tr::now);
			break;
		case MTP::ServerKeyStatus::Valid:
			// No default branch on purpose: adding a status must fail
			// the build until its message exists. This branch is not
			// reachable: !keyCheck means the status is not Valid.
			msg = tr::lng_intro_server_key_invalid(tr::now);
			break;
		}
		_key->showError();
		showError(rpl::single(msg));
		setAccessibleDescription(msg);
		QAccessibleEvent alertEvent(this, QAccessible::Alert);
		QAccessible::updateAccessibility(&alertEvent);
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

	_panelA11yBase = [&] {
		if (!_keyCheck.valid()) {
			return tr::lng_intro_server_check_title(tr::now);
		}
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
		return tr::lng_intro_server_check_value_a11y(
			tr::now,
			lt_groups,
			groupsString);
	}();
	_panel->setAccessibleName(_panelA11yBase);

	_compare->setAccessibleName(
		tr::lng_intro_server_check_ph(tr::now));

	_panel->paintRequest(
	) | rpl::on_next([=](QRect clip) {
		auto p = QPainter(_panel.data());
		paintPanel(p);
	}, _panel->lifetime());

	_panel->setLayoutDirection(Qt::LeftToRight);
	_panel->setFocusPolicy(Qt::TabFocus);
	_panel->setContextMenuPolicy(Qt::CustomContextMenu);
	QObject::connect(
		_panel.data(),
		&QWidget::customContextMenuRequested,
		[=](const QPoint &) {
			if (_keyCheck.valid()) {
				QGuiApplication::clipboard()->setText(_keyCheck.identity);
				getData()->controller->showToast(
					tr::lng_text_copied(tr::now));
			}
		});

	_compare->changes() | rpl::on_next([=] {
		updateVerdict();
	}, _compare->lifetime());

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

	const auto panelH = 182;
	_panel->setGeometry(panelX, panelY, panelW, panelH);

	const auto compareX = (panelW - st::introServerCompareField.width) / 2;
	_compare->moveToLeft(compareX, 65);

	const auto copyWidth = _copy->width();
	_copy->moveToLeft(panelW - copyWidth - 8, 152);
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
	if (!PaintIdentityRows(p, identity, _panel->width())) {
		p.setPen(st::windowSubTextFg->c);
		p.setFont(st::normalFont);
		const auto textX = 8;
		const auto innerW = _panel->width() - textX * 2;
		p.drawText(
			QRect(textX, 8, innerW, 50),
			tr::lng_intro_server_identity_too_wide(tr::now),
			QTextOption(Qt::AlignLeft | Qt::AlignTop));
	}

	p.setPen(st::shadowFg->c);
	p.drawLine(8, 58, _panel->width() - 8, 58);

	const auto verdictY = 152;
	const auto copyOffset = _copy
		? (_panel->width() - _copy->width() - 8)
		: _panel->width();
	const auto verdictMaxW = copyOffset - 12;
	const auto verdictRect = QRect(8, verdictY, verdictMaxW, 30);
	const auto textOpt = QTextOption(Qt::AlignLeft | Qt::AlignTop);
	switch (_compareStatus) {
	case MTP::KeyIdCompare::None:
		p.setPen(st::windowSubTextFg->c);
		p.drawText(verdictRect,
			tr::lng_intro_server_check_none(tr::now),
			textOpt);
		break;
	case MTP::KeyIdCompare::Match:
		p.setPen(st::activeLineFg->c);
		p.drawText(verdictRect,
			tr::lng_intro_server_check_match(tr::now),
			textOpt);
		break;
	case MTP::KeyIdCompare::Mismatch:
		p.setPen(st::boxTextFgError->c);
		p.drawText(verdictRect,
			tr::lng_intro_server_check_mismatch(tr::now),
			textOpt);
		break;
	case MTP::KeyIdCompare::Unreadable:
		p.setPen(st::windowSubTextFg->c);
		p.drawText(verdictRect,
			tr::lng_intro_server_check_unreadable(tr::now),
			textOpt);
		break;
	}
}

void ServerKeyWidget::updateVerdict() {
	hideError();
	setAccessibleDescription(QString());
	const auto typed = MTP::ExtractKeyId(_compare->getLastText());
	_compareStatus = MTP::CompareKeyId(typed, _keyCheck.identity);
	_panel->update();
	const auto verdictText = [&]() -> QString {
		switch (_compareStatus) {
		case MTP::KeyIdCompare::None: return tr::lng_intro_server_check_none(tr::now);
		case MTP::KeyIdCompare::Match: return tr::lng_intro_server_check_match(tr::now);
		case MTP::KeyIdCompare::Mismatch: return tr::lng_intro_server_check_mismatch(tr::now);
		case MTP::KeyIdCompare::Unreadable: return tr::lng_intro_server_check_unreadable(tr::now);
		}
		return {};
	}();
	_panel->setAccessibleName(
		verdictText.isEmpty()
			? _panelA11yBase
			: _panelA11yBase + u". "_q + verdictText);
	QAccessibleEvent nameEvent(_panel.data(), QAccessible::NameChanged);
	QAccessible::updateAccessibility(&nameEvent);
}

void ServerKeyWidget::commitAndAdvance() {
	if (!_endpoint || !_keyCheck) {
		return;
	}
	const auto key = std::make_shared<MTP::details::RSAPublicKey>(
		_keyCheck.key);
	if (!account().mtp().dcOptions().setCustomServer(MTP::CustomServer{
		.dcId = 2,
		.ip = _endpoint.host,
		.port = _endpoint.port,
		.ipv6 = _endpoint.ipv6,
		.key = key,
	})) {
		const auto setFailedMsg = tr::lng_intro_server_set_failed(tr::now);
		showError(rpl::single(setFailedMsg));
		setAccessibleDescription(setFailedMsg);
		QAccessibleEvent alertEvent(this, QAccessible::Alert);
		QAccessible::updateAccessibility(&alertEvent);
		return;
	}
	account().mtp().restart();
	goNext<PhoneWidget>();
}

void ServerKeyWidget::submit() {
	// An unreadable entry blocks like a mismatch: the user tried to
	// compare and produced nothing comparable, so nothing was verified.
	// Only an empty field (None) and a confirmed Match advance.
	if (!MTP::KeyIdCompareAllowsAdvance(_compareStatus)) {
		const auto msg = (_compareStatus == MTP::KeyIdCompare::Mismatch)
			? tr::lng_intro_server_check_mismatch(tr::now)
			: tr::lng_intro_server_check_unreadable(tr::now);
		showError(rpl::single(msg));
		setAccessibleDescription(msg);
		QAccessibleEvent alertEvent(this, QAccessible::Alert);
		QAccessible::updateAccessibility(&alertEvent);
		return;
	}
	commitAndAdvance();
}

} // namespace details
} // namespace Intro
