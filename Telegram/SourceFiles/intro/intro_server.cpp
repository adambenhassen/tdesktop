/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_server.h"

#include "intro/intro_username.h"
#include "intro/intro_widget.h"
#include "lang/lang_keys.h"
#include "main/main_account.h"
#include "main/main_app_config.h"
#include "main/main_domain.h"
#include "mtproto/mtproto_custom_server_input.h"
#include "mtproto/mtproto_dc_options.h"
#include "storage/storage_account.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "ui/widgets/scroll_area.h"
#include "ui/wrap/vertical_layout.h"
#include "ui/ui_utility.h"
#include "window/window_controller.h"
#include "styles/style_intro.h"

#include <QtGui/QAccessible>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>
#include <QtGui/QKeyEvent>
#include <QtGui/QPainter>
#include <QtGui/QFontMetrics>
#include <QtWidgets/QTextEdit>

#include <algorithm>
#include <memory>
#include <optional>

namespace Intro {
namespace details {
namespace {

constexpr auto kScrollTop = 124;
constexpr auto kPanelSideMargin = 20;
constexpr auto kFieldSideMargin = 40;

[[nodiscard]] const style::FlatLabel &IdentityLabelStyle() {
	static const auto result = [] {
		auto result = st::introServerIdentity;
		result.style.font = result.style.font->monospace();
		return result;
	}();
	return result;
}

[[nodiscard]] QString IdentityGroupsForAccessibility(const QString &identity) {
	auto result = QString();
	auto inGroup = 0;
	for (const auto ch : identity) {
		if (ch == QChar::fromLatin1('-')) {
			result += u", "_q;
			inGroup = 0;
		} else {
			if (inGroup > 0) {
				result += QChar::fromLatin1(' ');
			}
			result += ch;
			++inGroup;
		}
	}
	return result;
}

[[nodiscard]] QString IdentityRows(
		const QString &identity,
		int availableWidth) {
	const auto groups = identity.split(QChar::fromLatin1('-'));
	const auto font = IdentityLabelStyle().style.font->f;
	const auto metrics = QFontMetrics(font);
	for (const auto perRow : { 8, 4, 2 }) {
		auto fits = true;
		for (auto start = 0; start < groups.size(); start += perRow) {
			const auto row = groups.mid(start, perRow).join(
				QChar::fromLatin1('-'));
			const auto displayedRow = (start + perRow < groups.size())
				? row + QChar::fromLatin1('-')
				: row;
			if (metrics.horizontalAdvance(displayedRow) > availableWidth) {
				fits = false;
				break;
			}
		}
		if (fits) {
			auto rows = QString();
			for (auto start = 0; start < groups.size(); start += perRow) {
				if (!rows.isEmpty()) {
					rows += QChar::fromLatin1('\n');
				}
				rows += groups.mid(start, perRow).join(
					QChar::fromLatin1('-'));
				if (start + perRow < groups.size()) {
					rows += QChar::fromLatin1('-');
				}
			}
			return rows;
		}
	}
	return identity;
}

[[nodiscard]] QString EnrollmentErrorText(
		const MTP::ServerEnrollmentCheck &check) {
	// Common warning options disable switch diagnostics. Keep this mapping
	// exhaustive so every parser reason has its own accepted copy.
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic error "-Wswitch-enum"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch-enum"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(4:4062)
#pragma warning(error:4062)
#endif
	switch (check.status) {
	case MTP::ServerEnrollmentStatus::Valid:
		return {};
	case MTP::ServerEnrollmentStatus::MissingEndpoint:
		return tr::lng_intro_server_enrollment_missing_endpoint(tr::now);
	case MTP::ServerEnrollmentStatus::MissingKey:
		return tr::lng_intro_server_enrollment_missing_key(tr::now);
	case MTP::ServerEnrollmentStatus::MultipleEndpoints:
		return tr::lng_intro_server_enrollment_multiple_endpoints(tr::now);
	case MTP::ServerEnrollmentStatus::MultipleKeys:
		return tr::lng_intro_server_enrollment_multiple_keys(tr::now);
	case MTP::ServerEnrollmentStatus::TruncatedEnvelope:
		return tr::lng_intro_server_enrollment_truncated(tr::now);
	case MTP::ServerEnrollmentStatus::UnparseableEnvelope:
		return tr::lng_intro_server_enrollment_unparseable(tr::now);
	case MTP::ServerEnrollmentStatus::TrailingContent:
		return tr::lng_intro_server_enrollment_trailing(tr::now);
	case MTP::ServerEnrollmentStatus::EndpointNoPort:
		return tr::lng_intro_server_enrollment_endpoint_no_port(tr::now);
	case MTP::ServerEnrollmentStatus::EndpointBadPort:
		return tr::lng_intro_server_enrollment_endpoint_bad_port(tr::now);
	case MTP::ServerEnrollmentStatus::EndpointEmptyHost:
		return tr::lng_intro_server_enrollment_endpoint_empty_host(tr::now);
	case MTP::ServerEnrollmentStatus::EndpointBadHost:
		return tr::lng_intro_server_enrollment_endpoint_bad_host(tr::now);
	case MTP::ServerEnrollmentStatus::EndpointHostTooLong:
		return tr::lng_intro_server_enrollment_endpoint_host_too_long(tr::now);
	case MTP::ServerEnrollmentStatus::EndpointUnbracketedIPv6:
		return tr::lng_intro_server_enrollment_endpoint_ipv6(tr::now);
	case MTP::ServerEnrollmentStatus::UnreadableKey:
		return tr::lng_intro_server_enrollment_unreadable_key(tr::now);
	case MTP::ServerEnrollmentStatus::PrivateKey:
		return tr::lng_intro_server_enrollment_private_key(tr::now);
	case MTP::ServerEnrollmentStatus::NotRsaKey:
		return tr::lng_intro_server_enrollment_not_rsa(tr::now);
	case MTP::ServerEnrollmentStatus::BadModulusSize:
		return tr::lng_intro_server_enrollment_bad_modulus(
			tr::now,
			lt_bits,
			QString::number(check.modulusBits));
	case MTP::ServerEnrollmentStatus::InternalKeyError:
		return tr::lng_intro_server_enrollment_internal(tr::now);
	}
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
	Unexpected("Unhandled server enrollment status.");
	return {};
}

void ConfigureEnrollmentField(not_null<Ui::InputField*> field) {
	field->setSubmitSettings(Ui::InputField::SubmitSettings::None);
	field->setMarkdownReplacesEnabled(false);
	field->setInstantReplacesEnabled(rpl::single(false));
	field->rawTextEdit()->setAcceptRichText(false);
	field->rawTextEdit()->setInputMethodHints(
		Qt::ImhMultiLine
		| Qt::ImhNoPredictiveText
		| Qt::ImhNoAutoUppercase);
	field->rawTextEdit()->setTabChangesFocus(true);
}

void PaintPanel(
		not_null<Ui::VerticalLayout*> panel,
		not_null<Ui::FlatLabel*> compareLabel,
		QPainter &p) {
	const auto rect = panel->rect().adjusted(0, 0, -1, -1);
	p.setRenderHint(QPainter::Antialiasing);
	p.setPen(Qt::NoPen);
	p.setBrush(st::introServerPanelBg->b);
	p.drawRoundedRect(rect, st::introServerPanelRadius, st::introServerPanelRadius);
	p.setPen(st::shadowFg->c);
	const auto lineY = compareLabel->y() - 8;
	p.drawLine(8, lineY, panel->width() - 9, lineY);
}

} // namespace

ServerWidget::ServerWidget(
		QWidget *parent,
		not_null<Main::Account*> account,
		not_null<Data*> data)
: Step(parent, account, data)
, _scroll(this)
, _readOnly(readOnly()) {
	setTitleText(_readOnly
		? tr::lng_intro_server_saved_title()
		: tr::lng_intro_server_title());
	setDescriptionText(_readOnly
		? tr::lng_intro_server_saved_desc()
		: tr::lng_intro_server_enrollment_desc());

	_content = _scroll->setOwnedWidget(
		object_ptr<Ui::VerticalLayout>(_scroll));
	if (_readOnly) {
		setupReadOnly();
	} else {
		setupEnrollment();
	}
	layoutContent();
}

bool ServerWidget::readOnly() const {
	const auto custom = account().mtp().dcOptions().customServer();
	return custom.key
		&& account().mtp().dcOptions().isAuthorized(custom.dcId);
}

void ServerWidget::setupEnrollment() {
	_enrollmentLabel = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		tr::lng_intro_server_enrollment_label(),
		st::introDescription);
	_enrollment = Ui::CreateChild<Ui::InputField>(
		_content,
		st::introServerKeyField,
		Ui::InputField::Mode::MultiLine,
		tr::lng_intro_server_enrollment_ph());
	_status = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		QString(),
		st::introError);
	_review = Ui::CreateChild<Ui::RoundButton>(
		_content,
		tr::lng_intro_server_review(),
		st::introNextButton);

	_enrollment->setAccessibleName(
		tr::lng_intro_server_enrollment_ph(tr::now));
	_enrollment->setAccessibleDescription(
		tr::lng_intro_server_enrollment_label(tr::now));
	ConfigureEnrollmentField(_enrollment);
	_enrollment->changes() | rpl::on_next([=] {
		enrollmentChanged();
	}, _enrollment->lifetime());
	_review->setClickedCallback([=] { reviewEnrollment(); });
	_status->setTextColorOverride(st::boxTextFgError->c);

	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_enrollmentLabel),
		style::margins(kFieldSideMargin, 0, kFieldSideMargin, 8),
		style::al_justify);
	_content->add(
		object_ptr<Ui::InputField>::fromRaw(_enrollment),
		style::margins(kFieldSideMargin, 0, kFieldSideMargin, 8),
		style::al_justify);
	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_status),
		style::margins(kFieldSideMargin, 0, kFieldSideMargin, 0),
		style::al_justify);
	_content->add(
		object_ptr<Ui::RoundButton>::fromRaw(_review),
		style::margins(kFieldSideMargin, 16, kFieldSideMargin, 0),
		style::al_justify);
	_status->hide();
	QWidget::setTabOrder(_enrollment, _review);

	if (!getData()->serverEnrollmentArtifact.isEmpty()) {
		_suppressChanges = true;
		_enrollment->setText(getData()->serverEnrollmentArtifact);
		_suppressChanges = false;
	}
}

void ServerWidget::setupReadOnly() {
	const auto custom = account().mtp().dcOptions().customServer();
	const auto address = custom.ipv6
		? (u"["_q + QString::fromStdString(custom.ip) + u"]:"_q)
		: (QString::fromStdString(custom.ip) + u":"_q);
	const auto endpoint = address + QString::number(custom.port);
	const auto identity = custom.key
		? MTP::ServerKeyIdentity(*custom.key)
		: QString();

	_savedAddressLabel = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		tr::lng_intro_server_address_label(),
		st::introDescription);
	_savedAddress = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		endpoint,
		st::introDescription);
	_savedIdentityLabel = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		tr::lng_intro_server_identity_label(),
		st::introDescription);
	_savedIdentity = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		identity.isEmpty()
			? tr::lng_intro_server_saved_identity_unreadable(tr::now)
			: IdentityRows(identity, st::introServerPanelWidth - 16),
		IdentityLabelStyle());
	_savedIdentityRaw = identity;
	_savedCopy = Ui::CreateChild<Ui::LinkButton>(
		_content,
		tr::lng_intro_server_check_copy(tr::now));
	_savedStatus = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		QString(),
		st::introError);
	_addAccount = Ui::CreateChild<Ui::LinkButton>(
		_content,
		tr::lng_intro_server_add_account(tr::now));

	_savedAddress->setSelectable(true);
	_savedAddress->setLayoutDirection(Qt::LeftToRight);
	_savedAddress->setBreakEverywhere(true);
	_savedAddress->setFocusPolicy(Qt::TabFocus);
	_savedAddress->setContextCopyText(
		tr::lng_context_copy_selected(tr::now));
	_savedAddress->setAccessibleName(
		tr::lng_intro_server_address_label(tr::now));
	_savedIdentity->setSelectable(true);
	_savedIdentity->setLayoutDirection(Qt::LeftToRight);
	_savedIdentity->setFocusPolicy(Qt::TabFocus);
	_savedIdentity->setContextCopyText(
		tr::lng_context_copy_selected(tr::now));
	_savedIdentity->setAccessibleName(identity.isEmpty()
		? tr::lng_intro_server_saved_identity_unreadable(tr::now)
		: tr::lng_intro_server_check_value_a11y(
			tr::now,
			lt_groups,
			IdentityGroupsForAccessibility(identity)));
	_savedCopy->setClickedCallback([=] {
		if (!identity.isEmpty()) {
			QGuiApplication::clipboard()->setText(identity);
			getData()->controller->showToast(
				tr::lng_text_copied(tr::now));
		}
	});
	_savedCopy->setDisabled(identity.isEmpty());
	_addAccount->setClickedCallback([=] {
		Core::App().domain().addActivated(account().mtp().environment());
	});
	_savedStatus->setTextColorOverride(st::boxTextFgError->c);
	if (identity.isEmpty()) {
		_savedStatus->setText(
			tr::lng_intro_server_saved_identity_unreadable(tr::now));
		_savedStatus->show();
	} else {
		_savedStatus->hide();
	}

	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_savedAddressLabel),
		style::margins(kFieldSideMargin, 0, kFieldSideMargin, 8),
		style::al_justify);
	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_savedAddress),
		style::margins(kFieldSideMargin, 0, kFieldSideMargin, 16),
		style::al_justify);
	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_savedIdentityLabel),
		style::margins(kFieldSideMargin, 0, kFieldSideMargin, 8),
		style::al_justify);
	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_savedIdentity),
		style::margins(kPanelSideMargin, 0, kPanelSideMargin, 8),
		style::al_justify);
	_content->add(
		object_ptr<Ui::LinkButton>::fromRaw(_savedCopy),
		style::margins(kFieldSideMargin, 0, kFieldSideMargin, 8),
		style::al_left);
	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_savedStatus),
		style::margins(kFieldSideMargin, 0, kFieldSideMargin, 0),
		style::al_justify);
	_content->add(
		object_ptr<Ui::LinkButton>::fromRaw(_addAccount),
		style::margins(kFieldSideMargin, 16, kFieldSideMargin, 0),
		style::al_left);
	if (identity.isEmpty()) {
		_savedStatus->show();
	} else {
		_savedStatus->hide();
	}
	QWidget::setTabOrder(_savedAddress, _savedIdentity);
	QWidget::setTabOrder(_savedIdentity, _savedCopy);
	QWidget::setTabOrder(_savedCopy, _addAccount);
}

int ServerWidget::nextButtonTop() const {
	return contentTop() + st::introServerNextTop;
}

void ServerWidget::setInnerFocus() {
	if (_readOnly) {
		if (_savedAddress) {
			_savedAddress->setFocus(Qt::OtherFocusReason);
		}
	} else if (_enrollment) {
		_enrollment->setFocusFast();
	}
}

void ServerWidget::activate() {
	Step::activate();
	_scroll->show();
	if (_readOnly) {
		setInnerFocus();
	} else if (_enrollment) {
		_enrollment->show();
		if (getData()->selectServerEnrollment) {
			getData()->selectServerEnrollment = false;
			_enrollment->selectAll();
		}
		_enrollment->setFocusFast();
	}
}

void ServerWidget::submit() {
	reviewEnrollment();
}

void ServerWidget::cancelled() {
	if (_readOnly) {
		return;
	}
	++_reviewSerial;
	_privateKeyWarning = false;
	getData()->serverEnrollmentArtifact.clear();
	getData()->serverEnrollment.reset();
	getData()->serverEndpoint.clear();
}

void ServerWidget::resizeEvent(QResizeEvent *e) {
	Step::resizeEvent(e);
	layoutContent();
}

void ServerWidget::layoutContent() {
	const auto scrollWidth = std::min(st::introStepWidth, width());
	const auto scrollLeft = (width() - scrollWidth) / 2;
	const auto scrollHeight = std::max(0, height() - contentTop() - kScrollTop - 8);
	_scroll->setGeometry(
		scrollLeft,
		contentTop() + kScrollTop,
		scrollWidth,
		scrollHeight);
	_content->resizeToWidth(scrollWidth);
	if (_savedIdentity && !_savedIdentityRaw.isEmpty()) {
		const auto rows = IdentityRows(
			_savedIdentityRaw,
			std::max(_savedIdentity->width(), 1));
		if (rows != _savedIdentityRows) {
			_savedIdentityRows = rows;
			_savedIdentity->setText(rows);
		}
	}
}

QWidget *ServerWidget::firstTabWidget() const {
	return _readOnly
		? _savedAddress
		: _enrollment;
}

QWidget *ServerWidget::lastTabWidget() const {
	return _readOnly
		? _addAccount
		: _review;
}

QWidget *ServerWidget::nextButtonFocusWidget() const {
	return _readOnly
		? _addAccount
		: _review;
}

rpl::producer<QString> ServerWidget::nextButtonText() const {
	return rpl::single(QString());
}

void ServerWidget::enrollmentChanged() {
	if (_suppressChanges || !_enrollment) {
		return;
	}
	++_reviewSerial;
	_privateKeyWarning = false;
	getData()->serverEnrollmentArtifact.clear();
	getData()->serverEnrollment.reset();
	getData()->serverEndpoint.clear();
	_enrollment->hideError();
	clearEnrollmentStatus();
}

void ServerWidget::reviewEnrollment() {
	if (!_enrollment || _review->isDisabled()) {
		return;
	}
	const auto artifact = _enrollment->getLastText();
	if (artifact.isEmpty()) {
		if (!_privateKeyWarning) {
			_enrollment->hideError();
			clearEnrollmentStatus();
		}
		_enrollment->setFocusFast();
		return;
	}
	if (artifact.trimmed().isEmpty()) {
		const auto text = tr::lng_intro_server_enrollment_empty(tr::now);
		_enrollment->showError();
		_enrollment->setAccessibleDescription(text);
		showEnrollmentStatus(text, true);
		_enrollment->setFocusFast();
		return;
	}

	const auto serial = ++_reviewSerial;
	_review->setDisabled(true);
	_enrollment->setDisabled(true);
	_enrollment->setAccessibleDescription(
		tr::lng_intro_server_enrollment_checking(tr::now));
	showEnrollmentStatus(
		tr::lng_intro_server_enrollment_checking(tr::now),
		false);

	// CheckServerEnrollment is bounded to the pasted artifact and has no
	// transport-facing dependencies. Keep the serial check even though the
	// current parser is synchronous: it makes a future worker result unable
	// to restore a cancelled or edited draft.
	auto check = MTP::CheckServerEnrollment(artifact);
	if (serial != _reviewSerial
		|| !_enrollment
		|| artifact != _enrollment->getLastText()) {
		return;
	}
	_review->setDisabled(false);
	_enrollment->setDisabled(false);
	_enrollment->setAccessibleDescription(
		tr::lng_intro_server_enrollment_label(tr::now));
	if (!check) {
		getData()->serverEnrollmentArtifact.clear();
		getData()->serverEnrollment.reset();
		getData()->serverEndpoint.clear();
		if (check.status == MTP::ServerEnrollmentStatus::PrivateKey) {
			_privateKeyWarning = true;
			_suppressChanges = true;
			_enrollment->clear();
			_enrollment->rawTextEdit()->document()->clearUndoRedoStacks();
			_suppressChanges = false;
			getData()->serverEnrollmentArtifact.clear();
		}
		const auto text = EnrollmentErrorText(check);
		_enrollment->showError();
		_enrollment->setAccessibleDescription(text);
		showEnrollmentStatus(text, true);
		_enrollment->setFocusFast();
		return;
	}

	_privateKeyWarning = false;
	getData()->serverEnrollmentArtifact = artifact;
	getData()->serverEndpoint = QString::fromStdString(check.endpoint);
	getData()->serverEnrollment = std::move(check);
	clearEnrollmentStatus();
	goNext<ServerKeyWidget>();
}

void ServerWidget::showEnrollmentStatus(
		const QString &text,
		bool error) {
	if (!_status) {
		return;
	}
	_status->setTextColorOverride(error
		? std::optional<QColor>(st::boxTextFgError->c)
		: std::optional<QColor>(st::windowSubTextFg->c));
	_status->setText(text);
	_status->show();
	setAccessibleDescription(text);
	announceStatus();
}

void ServerWidget::clearEnrollmentStatus() {
	if (_status) {
		_status->setText(QString());
		_status->hide();
	}
	setAccessibleDescription(QString());
	if (_enrollment) {
		_enrollment->setAccessibleDescription(
			tr::lng_intro_server_enrollment_label(tr::now));
	}
}

void ServerWidget::announceStatus() {
	const auto event = QAccessibleEvent(this, QAccessible::Alert);
	QAccessible::updateAccessibility(&event);
}

ServerKeyWidget::ServerKeyWidget(
		QWidget *parent,
		not_null<Main::Account*> account,
		not_null<Data*> data)
: Step(parent, account, data)
, _scroll(this) {
	if (getData()->serverEnrollment) {
		_check = *getData()->serverEnrollment;
	}

	setTitleText(tr::lng_intro_server_check_title());
	setDescriptionText(tr::lng_intro_server_check_desc());

	_content = _scroll->setOwnedWidget(
		object_ptr<Ui::VerticalLayout>(_scroll));
	_endpointLabel = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		tr::lng_intro_server_address_label(),
		st::introDescription);
	_endpoint = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		QString::fromStdString(_check.endpoint),
		st::introDescription);
	_panel = Ui::CreateChild<Ui::VerticalLayout>(_content);
	_identityLabel = Ui::CreateChild<Ui::FlatLabel>(
		_panel,
		tr::lng_intro_server_identity_label(),
		st::introDescription);
	_identity = Ui::CreateChild<Ui::FlatLabel>(
		_panel,
		IdentityRows(
			_check.identity,
			st::introServerPanelWidth - 16),
		IdentityLabelStyle());
	_copy = Ui::CreateChild<Ui::LinkButton>(
		_panel,
		tr::lng_intro_server_check_copy(tr::now));
	_compareLabel = Ui::CreateChild<Ui::FlatLabel>(
		_panel,
		tr::lng_intro_server_key_id_label(),
		st::introDescription);
	_compare = Ui::CreateChild<Ui::InputField>(
		_panel,
		st::introServerCompareField,
		Ui::InputField::Mode::SingleLine,
		tr::lng_intro_server_check_ph());
	_verdict = Ui::CreateChild<Ui::FlatLabel>(
		_panel,
		QString(),
		st::introDescription);
	_verdictMeasure = Ui::CreateChild<Ui::FlatLabel>(
		_panel,
		QString(),
		st::introDescription);
	_verdictMeasure->hide();
	_secondary = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		tr::lng_intro_server_check_secondary(),
		st::introDescription);
	_replace = Ui::CreateChild<Ui::LinkButton>(
		_content,
		tr::lng_intro_server_replace(tr::now));
	_confirm = Ui::CreateChild<Ui::RoundButton>(
		_content,
		tr::lng_intro_server_confirm(tr::now),
		st::introNextButton);

	_endpoint->setSelectable(true);
	_endpoint->setLayoutDirection(Qt::LeftToRight);
	_endpoint->setBreakEverywhere(true);
	_endpoint->setFocusPolicy(Qt::TabFocus);
	_endpoint->setContextCopyText(tr::lng_context_copy_selected(tr::now));
	_endpoint->setAccessibleName(
		tr::lng_intro_server_address_label(tr::now));
	_identity->setSelectable(true);
	_identity->setLayoutDirection(Qt::LeftToRight);
	_identity->setFocusPolicy(Qt::TabFocus);
	_panelA11yBase = tr::lng_intro_server_check_value_a11y(
		tr::now,
		lt_groups,
		IdentityGroupsForAccessibility(_check.identity));
	_identity->setAccessibleName(_panelA11yBase);
	_identity->setContextCopyText(tr::lng_context_copy_selected(tr::now));

	ConfigureEnrollmentField(_compare);
	_compare->setMinHeight(st::introServerCompareField.heightMin);
	_compare->setMaxHeight(st::introServerCompareField.heightMin);
	_compare->setAccessibleName(
		tr::lng_intro_server_key_id_label(tr::now));
	_compare->setLayoutDirection(Qt::LeftToRight);
	_compare->rawTextEdit()->installEventFilter(this);
	_compare->changes() | rpl::on_next([=] {
		updateVerdict();
	}, _compare->lifetime());

	_copy->setClickedCallback([=] { copyIdentity(); });
	_replace->setClickedCallback([=] { replaceEnrollment(); });
	_confirm->setClickedCallback([=] { submit(); });

	_panel->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_identityLabel),
		style::margins(8, 12, 8, 4),
		style::al_justify);
	_panel->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_identity),
		style::margins(8, 0, 8, 8),
		style::al_justify);
	_panel->add(
		object_ptr<Ui::LinkButton>::fromRaw(_copy),
		style::margins(8, 0, 8, 12),
		style::al_left);
	_panel->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_compareLabel),
		style::margins(8, 8, 8, 4),
		style::al_justify);
	_panel->add(
		object_ptr<Ui::InputField>::fromRaw(_compare),
		style::margins(8, 0, 8, 8),
		style::al_justify);
	_panel->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_verdict),
		style::margins(8, 0, 8, 12),
		style::al_justify);

	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_endpointLabel),
		style::margins(kFieldSideMargin, 0, kFieldSideMargin, 8),
		style::al_justify);
	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_endpoint),
		style::margins(kFieldSideMargin, 0, kFieldSideMargin, 0),
		style::al_justify);
	_content->add(
		object_ptr<Ui::VerticalLayout>::fromRaw(_panel),
		style::margins(kPanelSideMargin, 16, kPanelSideMargin, 0),
		style::al_justify);
	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_secondary),
		style::margins(kFieldSideMargin, 16, kFieldSideMargin, 0),
		style::al_justify);
	_content->add(
		object_ptr<Ui::LinkButton>::fromRaw(_replace),
		style::margins(kFieldSideMargin, 12, kFieldSideMargin, 0),
		style::al_left);
	_content->add(
		object_ptr<Ui::RoundButton>::fromRaw(_confirm),
		style::margins(kFieldSideMargin, 16, kFieldSideMargin, 0),
		style::al_justify);
	QWidget::setTabOrder(_endpoint, _identity);
	QWidget::setTabOrder(_identity, _copy);
	QWidget::setTabOrder(_copy, _compare);
	QWidget::setTabOrder(_compare, _replace);
	QWidget::setTabOrder(_replace, _confirm);

	_panel->setNaturalWidth(st::introServerPanelWidth);
	setVerdict(MTP::KeyIdCompare::None);

	_panel->paintRequest() | rpl::on_next([=](QRect) {
		auto painter = QPainter(_panel);
		PaintPanel(_panel, _compareLabel, painter);
	}, _panel->lifetime());
	_panel->setLayoutDirection(Qt::LeftToRight);
	layoutContent();
}

int ServerKeyWidget::nextButtonTop() const {
	return contentTop() + st::introServerNextTop;
}

void ServerKeyWidget::setInnerFocus() {
	if (_endpoint) {
		_endpoint->setFocus(Qt::OtherFocusReason);
	}
}

void ServerKeyWidget::activate() {
	Step::activate();
	if (_confirming
		&& !account().sessionExists()
		&& !account().mtp().dcOptions().isAuthorized(2)) {
		// Returning from a credential step after the pin was committed leaves
		// this step in the history. It is eligible for correction until auth
		// creates server-scoped account data, so make the deliberate replace
		// path usable again instead of trapping the user in "Saving server…".
		_confirming = false;
		_confirm->setText(tr::lng_intro_server_confirm());
		_confirm->setDisabled(
			!MTP::KeyIdCompareAllowsAdvance(_compareStatus));
		_compare->setDisabled(false);
		_replace->setDisabled(false);
	}
	_scroll->show();
	setInnerFocus();
}

void ServerKeyWidget::cancelled() {
	if (account().sessionExists()
		|| account().mtp().dcOptions().isAuthorized(2)) {
		return;
	}
	getData()->selectServerEnrollment = true;

	// Credential widgets cancel their own in-flight requests when Back pops
	// them. Stop this account's transport as well, then discard every value
	// that could otherwise be reused after the enrollment is corrected.
	account().mtp().stopForServerEnrollment();
	getData()->phone.clear();
	getData()->phoneHash.clear();
	getData()->pwdState = {};
	getData()->usernameCode.drop();
	getData()->signupName.clear();
	getData()->usernameError.clear();
	getData()->signupNameError.clear();
	getData()->email.clear();
	getData()->emailPatternSetup.clear();
	getData()->emailPatternLogin.clear();
	getData()->emailStatus = EmailStatus::None;
	getData()->termsLock = Window::TermsLock();
}

void ServerKeyWidget::resizeEvent(QResizeEvent *e) {
	Step::resizeEvent(e);
	layoutContent();
}

void ServerKeyWidget::keyPressEvent(QKeyEvent *e) {
	if (e->key() == Qt::Key_Enter || e->key() == Qt::Key_Return) {
		e->accept();
		return;
	}
	QWidget::keyPressEvent(e);
}

void ServerKeyWidget::layoutContent() {
	const auto scrollWidth = std::min(st::introStepWidth, width());
	const auto scrollLeft = (width() - scrollWidth) / 2;
	const auto scrollHeight = std::max(0, height() - contentTop() - kScrollTop - 8);
	_scroll->setGeometry(
		scrollLeft,
		contentTop() + kScrollTop,
		scrollWidth,
		scrollHeight);
	_content->resizeToWidth(scrollWidth);
	reserveVerdictHeight();
	if (_identity && !_check.identity.isEmpty()) {
		const auto rows = IdentityRows(
			_check.identity,
			std::max(_identity->width(), 1));
		if (rows != _identityRows) {
			_identityRows = rows;
			_identity->setText(rows);
		}
	}
	_panel->update();
}

void ServerKeyWidget::reserveVerdictHeight() {
	if (!_verdict || !_verdictMeasure) {
		return;
	}
	const auto width = std::max(_verdict->width(), 1);
	const auto verdicts = {
		tr::lng_intro_server_check_none(tr::now),
		tr::lng_intro_server_check_unreadable(tr::now),
		tr::lng_intro_server_check_match(tr::now),
		tr::lng_intro_server_check_mismatch(tr::now),
		tr::lng_intro_server_save_failed(tr::now),
	};
	auto height = 0;
	for (const auto &text : verdicts) {
		_verdictMeasure->setText(text);
		_verdictMeasure->resizeToWidth(width);
		height = std::max(height, _verdictMeasure->height());
	}
	_verdict->setMinimumHeight(height);
}

QWidget *ServerKeyWidget::firstTabWidget() const {
	return _endpoint;
}

QWidget *ServerKeyWidget::lastTabWidget() const {
	return _confirm;
}

QWidget *ServerKeyWidget::nextButtonFocusWidget() const {
	return _confirm;
}

rpl::producer<QString> ServerKeyWidget::nextButtonText() const {
	return rpl::single(QString());
}

bool ServerKeyWidget::eventFilter(QObject *receiver, QEvent *event) {
	if (receiver == _compare->rawTextEdit()
		&& event->type() == QEvent::KeyPress) {
		const auto key = static_cast<QKeyEvent*>(event)->key();
		if (key == Qt::Key_Enter || key == Qt::Key_Return) {
			event->accept();
			return true;
		}
	}
	return QWidget::eventFilter(receiver, event);
}

void ServerKeyWidget::updateVerdict() {
	if (_confirming || _saveFailed) {
		return;
	}
	const auto typed = MTP::ExtractKeyId(_compare->getLastText());
	setVerdict(MTP::CompareKeyId(typed, _check.identity));
}

void ServerKeyWidget::setVerdict(MTP::KeyIdCompare status) {
	const auto changed = (_compareStatus != status);
	_compareStatus = status;
	QString text;
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic error "-Wswitch-enum"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch-enum"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(4:4062)
#pragma warning(error:4062)
#endif
	switch (_compareStatus) {
	case MTP::KeyIdCompare::None:
		text = tr::lng_intro_server_check_none(tr::now);
		_verdict->setTextColorOverride(st::windowSubTextFg->c);
		break;
	case MTP::KeyIdCompare::Unreadable:
		text = tr::lng_intro_server_check_unreadable(tr::now);
		_verdict->setTextColorOverride(st::boxTextFgError->c);
		break;
	case MTP::KeyIdCompare::Mismatch:
		text = tr::lng_intro_server_check_mismatch(tr::now);
		_verdict->setTextColorOverride(st::boxTextFgError->c);
		break;
	case MTP::KeyIdCompare::Match:
		text = tr::lng_intro_server_check_match(tr::now);
		_verdict->setTextColorOverride(st::activeLineFg->c);
		break;
	}
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
	_verdict->setText(text);
	_verdict->setAccessibleName(text);
	_compare->setAccessibleDescription(text);
	setAccessibleDescription(text);
	_confirm->setDisabled(!MTP::KeyIdCompareAllowsAdvance(_compareStatus));
	_panel->update();
	if (changed) {
		announceVerdict();
	}
}

void ServerKeyWidget::showSaveFailure() {
	const auto text = tr::lng_intro_server_save_failed(tr::now);
	_saveFailed = true;
	_confirm->setDisabled(true);
	_compare->setDisabled(true);
	_verdict->setTextColorOverride(st::boxTextFgError->c);
	_verdict->setText(text);
	_verdict->setAccessibleName(text);
	_compare->setAccessibleDescription(text);
	setAccessibleDescription(text);
	_panel->update();
	announceVerdict();
}

void ServerKeyWidget::announceVerdict() {
	const auto event = QAccessibleEvent(_verdict, QAccessible::Alert);
	QAccessible::updateAccessibility(&event);
}

void ServerKeyWidget::copyIdentity() {
	if (_check.identity.isEmpty()) {
		return;
	}
	QGuiApplication::clipboard()->setText(_check.identity);
	getData()->controller->showToast(tr::lng_text_copied(tr::now));
}

void ServerKeyWidget::replaceEnrollment() {
	if (account().sessionExists()
		|| account().mtp().dcOptions().isAuthorized(2)) {
		showSaveFailure();
		return;
	}
	getData()->selectServerEnrollment = true;
	goBack();
}

void ServerKeyWidget::commitAndAdvance() {
	if (_confirming
		|| !_check.valid()
		|| !_check.key.valid()
		|| _compareStatus != MTP::KeyIdCompare::Match) {
		return;
	}

	const auto endpointCheck = MTP::CheckServerEndpoint(
		QString::fromStdString(_check.endpoint));
	if (!endpointCheck) {
		showSaveFailure();
		return;
	}
	if (account().sessionExists()
		|| account().mtp().dcOptions().isAuthorized(2)) {
		showSaveFailure();
		return;
	}

	_confirming = true;
	_confirm->setText(tr::lng_intro_server_saving());
	_confirm->setDisabled(true);
	_compare->setDisabled(true);
	_replace->setDisabled(true);

	const auto key = std::make_shared<MTP::details::RSAPublicKey>(_check.key);
	const auto server = MTP::CustomServer{
		.dcId = 2,
		.ip = endpointCheck.host,
		.port = endpointCheck.port,
		.ipv6 = endpointCheck.ipv6,
		.key = key,
	};
	if (!account().mtp().dcOptions().setCustomServer(server)) {
		const auto current = account().mtp().dcOptions().customServer();
		if (current.key
			&& account().mtp().dcOptions().isAuthorized(current.dcId)) {
			// Another path authorized this account between the eligibility
			// check and the pin write. Rebuild the step as the immutable
			// read-only view instead of offering an enrollment edit.
			goReplace<ServerWidget>(Animate::Back);
			return;
		}
		_confirming = false;
		_confirm->setText(tr::lng_intro_server_confirm());
		_replace->setDisabled(false);
		showSaveFailure();
		return;
	}

	// The marker and serialized pin are written before resume() creates the
	// first session. A crash after this point fails closed on the next start.
	account().local().writeMtpConfig();
	getData()->serverEndpoint = QString::fromStdString(_check.endpoint);
	account().mtp().resume();
	goNext<UsernameWidget>();
}

void ServerKeyWidget::submit() {
	if (!MTP::KeyIdCompareAllowsAdvance(_compareStatus)) {
		return;
	}
	commitAndAdvance();
}

} // namespace details
} // namespace Intro
