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
#include "main/main_domain.h"
#include "mtproto/mtproto_dc_options.h"
#include "mtproto/mtproto_server_enrollment.h"
#include "storage/storage_account.h"
#include "base/random.h"
#include "core/application.h"
#include "ui/widgets/buttons.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/labels.h"
#include "ui/widgets/scroll_area.h"
#include "ui/wrap/vertical_layout.h"
#include "window/window_controller.h"
#include "styles/style_intro.h"

#include <QtCore/QTimer>
#include <QtGui/QAccessible>
#include <QtGui/QColor>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QSslError>
#include <QtNetwork/QTcpSocket>
#include <QtWidgets/QTextEdit>

#include <algorithm>
#include <optional>
#include <utility>

namespace Intro {
namespace details {
namespace {

constexpr auto kDiscoveryTimeout = 10 * 1000;
constexpr auto kMaxDiscoveryBody = 16 * 1024;
constexpr auto kMaxDiscoveryHeaders = 16 * 1024;

void ConfigureAddressField(not_null<Ui::InputField*> field) {
	field->setSubmitSettings(Ui::InputField::SubmitSettings::None);
	field->setMarkdownReplacesEnabled(false);
	field->setInstantReplacesEnabled(rpl::single(false));
	field->rawTextEdit()->setAcceptRichText(false);
	field->rawTextEdit()->setInputMethodHints(
		Qt::ImhNoPredictiveText
		| Qt::ImhNoAutoUppercase);
	field->rawTextEdit()->setTabChangesFocus(true);
}

[[nodiscard]] QString CustomServerEndpoint(const MTP::CustomServer &server) {
	const auto host = QString::fromStdString(server.ip);
	return (server.ipv6 ? (u"["_q + host + u"]"_q) : host)
		+ u":"_q
		+ QString::number(server.port);
}

[[nodiscard]] QString AddressWithPort(
		const QHostAddress &address,
		int port) {
	const auto host = address.toString();
	return (address.protocol() == QAbstractSocket::IPv6Protocol
		? (u"["_q + host + u"]"_q)
		: host)
		+ u":"_q
		+ QString::number(port);
}

[[nodiscard]] bool HasBoundServer(Main::Account &account) {
	const auto &options = account.mtp().dcOptions();
	return options.hasCustomServer() || options.blocked();
}

[[nodiscard]] bool IsCompleteLocalResponse(const QByteArray &response) {
	if (response.size() < 58) {
		return false;
	}
	const auto read32 = [&](int offset) {
		return (quint32(uchar(response[offset])) << 24)
			| (quint32(uchar(response[offset + 1])) << 16)
			| (quint32(uchar(response[offset + 2])) << 8)
			| quint32(uchar(response[offset + 3]));
	};
	const auto bodyLength = read32(48);
	if (bodyLength < 7 || bodyLength > 4102) {
		return false;
	}
	return response.size() >= 58 + int(bodyLength);
}

[[nodiscard]] bool DiscoveryHeadersWithinBound(
		QNetworkReply *reply) {
	auto size = 0;
	for (const auto &header : reply->rawHeaderPairs()) {
		size += header.first.size() + header.second.size() + 4;
		if (size > kMaxDiscoveryHeaders) {
			return false;
		}
	}
	return true;
}

} // namespace

ServerWidget::ServerWidget(
		QWidget *parent,
		not_null<Main::Account*> account,
		not_null<Data*> data)
: Step(parent, account, data)
, _scroll(this)
, _deadline(new QTimer(this))
, _readOnly(readOnly()) {
	_deadline->setSingleShot(true);
	connect(_deadline, &QTimer::timeout, this, [=] {
		discoveryTimeout();
	});

	setTitleText(_readOnly
		? tr::lng_intro_server_saved_title()
		: tr::lng_intro_server_title());
	setDescriptionText(_readOnly
		? tr::lng_intro_server_saved_desc()
		: tr::lng_intro_server_desc());

	_content = _scroll->setOwnedWidget(
		object_ptr<Ui::VerticalLayout>(_scroll));
	setupSelection();
	setupBound();
	if (!_readOnly) {
		_savedAddressLabel->hide();
		_savedAddress->hide();
		_savedStatus->hide();
		_savedContinue->hide();
		_addAccount->hide();
	} else {
		_addressLabel->hide();
		_address->hide();
		_status->hide();
		_continue->hide();
	}
	descriptionGeometryValue() | rpl::on_next([=](QRect) {
		if (_content) {
			layoutContent();
		}
	}, lifetime());
	layoutContent();
}

bool ServerWidget::readOnly() const {
	return HasBoundServer(account());
}

void ServerWidget::setupSelection() {
	_addressLabel = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		tr::lng_intro_server_address_label(),
		st::introDescription);
	_address = Ui::CreateChild<Ui::InputField>(
		_content,
		st::introCountry,
		Ui::InputField::Mode::SingleLine,
		tr::lng_intro_server_address_ph());
	_status = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		QString(),
		st::introError);
	_continue = Ui::CreateChild<Ui::RoundButton>(
		_content,
		tr::lng_intro_server_continue(),
		st::introNextButton);

	_address->setAccessibleName(
		tr::lng_intro_server_address_label(tr::now));
	_address->setAccessibleDescription(
		tr::lng_intro_server_address_ph(tr::now));
	ConfigureAddressField(_address);
	_address->changes() | rpl::on_next([=] {
		selectionChanged();
	}, _address->lifetime());
	_address->submits() | rpl::on_next([=](Qt::KeyboardModifiers) {
		submitSelection();
	}, _address->lifetime());
	_continue->setClickedCallback([=] {
		submitSelection();
	});
	_status->setTextColorOverride(st::boxTextFgError->c);

	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_addressLabel),
		st::introServerAddressLabelMargins,
		style::al_justify);
	_content->add(
		object_ptr<Ui::InputField>::fromRaw(_address),
		st::introServerAddressFieldMargins,
		style::al_justify);
	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_status),
		st::introServerAddressStatusMargins,
		style::al_justify);
	_content->add(
		object_ptr<Ui::RoundButton>::fromRaw(_continue),
		st::introServerAddressButtonMargins,
		style::al_justify);
	_status->hide();
	QWidget::setTabOrder(_address, _continue);

	if (!getData()->serverSelection.isEmpty()) {
		_suppressChanges = true;
		_address->setText(getData()->serverSelection);
		_suppressChanges = false;
	}
}

void ServerWidget::setupBound() {
	const auto blocked = account().mtp().dcOptions().blocked();
	const auto authorized = account().sessionExists();
	const auto custom = account().mtp().dcOptions().customServer();
	const auto endpoint = custom.serverSelection.empty()
		? (custom.empty() ? QString() : CustomServerEndpoint(custom))
		: QString::fromStdString(custom.serverSelection);
	_savedAddressLabel = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		tr::lng_intro_server_address_label(),
		st::introDescription);
	_savedAddress = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		endpoint,
		st::introDescription);
	_savedStatus = Ui::CreateChild<Ui::FlatLabel>(
		_content,
		QString(),
		st::introError);
	_savedContinue = Ui::CreateChild<Ui::RoundButton>(
		_content,
		tr::lng_intro_server_continue(),
		st::introNextButton);
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
	_savedStatus->setTextColorOverride(st::boxTextFgError->c);
	_savedContinue->setClickedCallback([=] {
		submit();
	});
	_addAccount->setClickedCallback([=] {
		Core::App().domain().addActivated(account().mtp().environment());
	});

	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_savedAddressLabel),
		st::introServerSavedAddressLabelMargins,
		style::al_justify);
	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_savedAddress),
		st::introServerSavedAddressMargins,
		style::al_justify);
	_content->add(
		object_ptr<Ui::FlatLabel>::fromRaw(_savedStatus),
		st::introServerSavedStatusMargins,
		style::al_justify);
	_content->add(
		object_ptr<Ui::RoundButton>::fromRaw(_savedContinue),
		st::introServerSavedContinueMargins,
		style::al_justify);
	_content->add(
		object_ptr<Ui::LinkButton>::fromRaw(_addAccount),
		st::introServerAddAccountMargins,
		style::al_left);
	_savedStatus->hide();

	if (blocked) {
		_savedStatus->setText(
			tr::lng_intro_server_saved_settings_unreadable(tr::now));
		_savedStatus->show();
		_savedContinue->setDisabled(true);
		_savedAddressLabel->hide();
		_savedAddress->hide();
		_savedContinue->hide();
	} else if (authorized) {
		_savedContinue->hide();
	}
	if (!endpoint.isEmpty()) {
		QWidget::setTabOrder(_savedAddress, (!blocked && !authorized)
			? static_cast<QWidget*>(_savedContinue)
			: static_cast<QWidget*>(_addAccount));
	}
	if (!blocked && !authorized) {
		QWidget::setTabOrder(_savedContinue, _addAccount);
	}
}

void ServerWidget::switchToBound() {
	_readOnly = true;
	setTitleText(tr::lng_intro_server_saved_title());
	setDescriptionText(tr::lng_intro_server_saved_desc());
	_addressLabel->hide();
	_address->hide();
	_status->hide();
	_continue->hide();
	_savedAddressLabel->show();
	_savedAddress->show();
	_savedContinue->show();
	_addAccount->show();
	const auto custom = account().mtp().dcOptions().customServer();
	_savedAddress->setText(custom.serverSelection.empty()
		? CustomServerEndpoint(custom)
		: QString::fromStdString(custom.serverSelection));
	if (account().mtp().dcOptions().blocked()) {
		_savedStatus->setText(
			tr::lng_intro_server_saved_settings_unreadable(tr::now));
		_savedStatus->show();
		_savedContinue->setDisabled(true);
	}
	layoutContent();
}

int ServerWidget::nextButtonTop() const {
	return contentTop() + st::introServerNextTop;
}

void ServerWidget::setInnerFocus() {
	if (_readOnly) {
		if (account().mtp().dcOptions().blocked()
			|| account().sessionExists()) {
			_addAccount->setFocus(Qt::OtherFocusReason);
		} else {
			_savedContinue->setFocus(Qt::OtherFocusReason);
		}
	} else {
		_address->setFocusFast();
	}
}

void ServerWidget::activate() {
	Step::activate();
	_scroll->show();
	if (!_readOnly && readOnly()) {
		switchToBound();
	}
	setInnerFocus();
}

void ServerWidget::submit() {
	if (!_readOnly) {
		submitSelection();
		return;
	}
	if (account().mtp().dcOptions().blocked()) {
		return;
	}
	if (account().sessionExists()) {
		return;
	}
	// A freshly restarted account is intentionally paused until its stored
	// binding is selected again. The binding was durably committed before
	// this point, so resuming here cannot send an unbound request.
	account().mtp().resume();
	getData()->serverEndpoint = CustomServerEndpoint(
		account().mtp().dcOptions().customServer());
	goNext<UsernameWidget>();
}

void ServerWidget::cancelled() {
	if (_connecting) {
		cancelDiscovery();
	}
	if (_readOnly) {
		return;
	}
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

void ServerWidget::resizeEvent(QResizeEvent *e) {
	Step::resizeEvent(e);
	layoutContent();
}

void ServerWidget::layoutContent() {
	const auto scrollWidth = std::min(st::introStepWidth, width());
	const auto scrollLeft = (width() - scrollWidth) / 2;
	const auto scrollTop = std::max(
		st::introServerScrollTop,
		descriptionBottom() - contentTop() + st::introServerScrollGap);
	const auto scrollHeight = std::max(
		0,
		height() - contentTop() - scrollTop - st::introServerScrollBottom);
	_scroll->setGeometry(
		scrollLeft,
		contentTop() + scrollTop,
		scrollWidth,
		scrollHeight);
	_content->resizeToWidth(scrollWidth);
}

QWidget *ServerWidget::firstTabWidget() const {
	if (_readOnly && account().mtp().dcOptions().blocked()) {
		return _addAccount;
	}
	return _readOnly
		? static_cast<QWidget*>(_savedAddress)
		: static_cast<QWidget*>(_address);
}

QWidget *ServerWidget::lastTabWidget() const {
	return _readOnly
		? static_cast<QWidget*>(_addAccount)
		: static_cast<QWidget*>(_continue);
}

QWidget *ServerWidget::nextButtonFocusWidget() const {
	if (!_readOnly) {
		return _continue;
	} else if (account().mtp().dcOptions().blocked()
		|| account().sessionExists()) {
		return _addAccount;
	} else {
		return _savedContinue;
	}
}

rpl::producer<QString> ServerWidget::nextButtonText() const {
	return rpl::single(QString());
}

void ServerWidget::selectionChanged() {
	if (_suppressChanges || !_address || _connecting) {
		return;
	}
	getData()->serverSelection = _address->getLastText();
	_address->hideError();
	clearStatus();
	_continue->setText(tr::lng_intro_server_continue());
}

QString ServerWidget::selectionError(MTP::ServerSelectionStatus status) const {
	switch (status) {
	case MTP::ServerSelectionStatus::Valid:
		return {};
	case MTP::ServerSelectionStatus::Empty:
		return tr::lng_intro_server_address_empty(tr::now);
	case MTP::ServerSelectionStatus::NoPort:
		return tr::lng_intro_server_address_no_port(tr::now);
	case MTP::ServerSelectionStatus::BadPort:
		return tr::lng_intro_server_address_bad_port(tr::now);
	case MTP::ServerSelectionStatus::EmptyHost:
		return tr::lng_intro_server_address_empty_host(tr::now);
	case MTP::ServerSelectionStatus::BadHost:
		return tr::lng_intro_server_address_invalid(tr::now);
	case MTP::ServerSelectionStatus::HostTooLong:
		return tr::lng_intro_server_address_too_long(tr::now);
	case MTP::ServerSelectionStatus::UnbracketedIPv6:
		return tr::lng_intro_server_address_ipv6(tr::now);
	case MTP::ServerSelectionStatus::InvalidSpecialAddress:
		return tr::lng_intro_server_address_invalid(tr::now);
	}
	Unexpected("Unhandled server selection status.");
}

void ServerWidget::submitSelection() {
	if (_readOnly || _connecting || !_address) {
		return;
	}
	const auto checked = MTP::CheckServerSelection(_address->getLastText());
	if (!checked) {
		_address->showError();
		showStatus(selectionError(checked.status), true);
		_address->setFocusFast();
		return;
	}
	_selection = checked;
	getData()->serverSelection = _selection.normalizedSelection;
	_connecting = true;
	++_attempt;
	_address->rawTextEdit()->setReadOnly(true);
	_continue->setDisabled(true);
	_continue->setText(tr::lng_intro_server_connecting());
	_address->setAccessibleDescription(
		tr::lng_intro_server_connecting(tr::now));
	showStatus(tr::lng_intro_server_connecting(tr::now), false);
	_deadline->start(kDiscoveryTimeout);
	if (_selection.policy == MTP::ServerDiscoveryPolicy::PublicHttps) {
		beginPublicDiscovery();
	} else {
		beginLocalDiscovery();
	}
}

void ServerWidget::beginPublicDiscovery() {
	if (!_network) {
		_network = new QNetworkAccessManager(this);
		_network->setProxy(QNetworkProxy::NoProxy);
	}
	_publicResponse.clear();
	const auto url = QUrl(MTP::PublicDiscoveryUrl(_selection));
	QNetworkRequest request(url);
	request.setAttribute(
		QNetworkRequest::RedirectPolicyAttribute,
		QNetworkRequest::ManualRedirectPolicy);
	request.setAttribute(
		QNetworkRequest::CacheLoadControlAttribute,
		QNetworkRequest::AlwaysNetwork);
	request.setAttribute(
		QNetworkRequest::CacheSaveControlAttribute,
		false);
	_reply = _network->get(request);
	const auto reply = _reply;
	reply->setReadBufferSize(kMaxDiscoveryBody);
	connect(reply, &QNetworkReply::readyRead, this, [=] {
		if (!_connecting || _reply != reply) {
			return;
		}
		if (!DiscoveryHeadersWithinBound(reply)) {
			discoveryFailed(false);
			return;
		}
		const auto contentLength = reply->header(
			QNetworkRequest::ContentLengthHeader).toLongLong();
		if (contentLength > kMaxDiscoveryBody) {
			discoveryFailed(false);
			return;
		}
		_publicResponse += reply->readAll();
		if (_publicResponse.size() > kMaxDiscoveryBody) {
			discoveryFailed(false);
		}
	});
	connect(reply, &QNetworkReply::sslErrors, this, [=](const auto &) {
		if (_connecting && _reply == reply) {
			discoveryFailed(false);
		}
	});
	connect(reply, &QNetworkReply::redirected, this, [=](const QUrl &) {
		if (_connecting && _reply == reply) {
			discoveryFailed(false);
		}
	});
	connect(reply, &QNetworkReply::finished, this, [=] {
		if (!_connecting || _reply != reply) {
			return;
		}
		if (reply->error() != QNetworkReply::NoError) {
			discoveryFailed(true);
			return;
		}
		if (!DiscoveryHeadersWithinBound(reply)) {
			discoveryFailed(false);
			return;
		}
		const auto status = reply->attribute(
			QNetworkRequest::HttpStatusCodeAttribute).toInt();
		const auto contentType = reply->header(
			QNetworkRequest::ContentTypeHeader).toString()
			.section(QChar::fromLatin1(';'), 0, 0)
			.trimmed();
		_publicResponse += reply->readAll();
		if (status != 200
			|| contentType.compare(
				u"application/json"_q,
				Qt::CaseInsensitive) != 0
			|| !reply->rawHeader("Content-Encoding").isEmpty()
			|| _publicResponse.size() > kMaxDiscoveryBody) {
			discoveryFailed(false);
			return;
		}
		discoveryFinished(MTP::ParsePublicDiscoveryResponse(
			_selection,
			_publicResponse));
	});
}

void ServerWidget::beginLocalDiscovery() {
	_localNonce.resize(32);
	base::RandomFill(_localNonce.data(), _localNonce.size());
	_localRequest = MTP::BuildLocalDiscoveryRequest(_localNonce);
	_localResponse.clear();
	_localWriteOffset = 0;
	_localWriteClosed = false;
	_socket = new QTcpSocket(this);
	_socket->setProxy(QNetworkProxy::NoProxy);
	const auto socket = _socket;
	connect(socket, &QTcpSocket::connected, this, [=] {
		if (_connecting && _socket == socket) {
			sendLocalRequest();
		}
	});
	connect(socket, &QTcpSocket::bytesWritten, this, [=](qint64) {
		if (_connecting && _socket == socket) {
			sendLocalRequest();
		}
	});
	connect(socket, &QTcpSocket::readyRead, this, [=] {
		if (_connecting && _socket == socket) {
			localReadyRead();
		}
	});
	connect(socket, &QTcpSocket::errorOccurred, this,
		[=](QAbstractSocket::SocketError error) {
		if (_connecting
			&& _socket == socket
			&& error != QAbstractSocket::RemoteHostClosedError) {
			discoveryFailed(true);
		}
	});
	connect(socket, &QTcpSocket::disconnected, this, [=] {
		if (!_connecting || _socket != socket) {
			return;
		}
		_localResponse += socket->readAll();
		if (_localResponse.size() > kMaxDiscoveryBody) {
			discoveryFailed(false);
			return;
		}
		if (!IsCompleteLocalResponse(_localResponse)) {
			discoveryFailed(false);
			return;
		}
		discoveryFinished(MTP::ParseLocalDiscoveryResponse(
			_selection,
			_localNonce,
			_localResponse));
	});
	socket->connectToHost(_selection.host, _selection.operationalPort);
}

void ServerWidget::sendLocalRequest() {
	if (!_socket || !_connecting || _localWriteClosed) {
		return;
	}
	while (_localWriteOffset < _localRequest.size()) {
		const auto written = _socket->write(
			_localRequest.constData() + _localWriteOffset,
			_localRequest.size() - _localWriteOffset);
		if (written < 0) {
			discoveryFailed(true);
			return;
		}
		if (written == 0) {
			return;
		}
		_localWriteOffset += int(written);
	}
	_localWriteClosed = true;
	// QTcpSocket drains queued bytes before closing its write side. The
	// server therefore observes EOF while its response remains readable.
	_socket->disconnectFromHost();
}

void ServerWidget::localReadyRead() {
	if (!_socket) {
		return;
	}
	_localResponse += _socket->readAll();
	if (_localResponse.size() > kMaxDiscoveryBody) {
		discoveryFailed(false);
		return;
	}
}

void ServerWidget::discoveryTimeout() {
	if (_connecting) {
		discoveryFailed(true);
	}
}

void ServerWidget::discoveryFinished(MTP::ServerDiscoveryResult result) {
	if (!_connecting) {
		return;
	}
	if (!result) {
		discoveryFailed(false);
		return;
	}
	if (_reply) {
		const auto reply = _reply;
		_reply = nullptr;
		reply->deleteLater();
	}
	if (_socket) {
		if (result.policy == MTP::ServerDiscoveryPolicy::LocalDirect) {
			const auto peer = _socket->peerAddress();
			if (!peer.isNull()) {
				result.resolvedAddress = peer.toString();
			}
		}
		const auto socket = _socket;
		_socket = nullptr;
		socket->abort();
		socket->deleteLater();
	}
	if (result.policy == MTP::ServerDiscoveryPolicy::PublicHttps) {
		resolvePublicEndpoint(std::move(result));
	} else {
		_deadline->stop();
		commitBinding(std::move(result));
	}
}

void ServerWidget::resolvePublicEndpoint(
		MTP::ServerDiscoveryResult result) {
	const auto endpoint = MTP::CheckServerSelection(result.endpoint);
	if (!MTP::IsPublicDiscoveryEndpoint(endpoint)) {
		discoveryFailed(false);
		return;
	}
	auto address = QHostAddress();
	if (address.setAddress(endpoint.host)) {
		if (address.protocol() != QAbstractSocket::IPv4Protocol
			&& address.protocol() != QAbstractSocket::IPv6Protocol) {
			discoveryFailed(false);
			return;
		}
		if (!MTP::IsPublicAddress(address)) {
			discoveryFailed(false);
			return;
		}
		result.resolvedAddress = address.toString();
		commitBinding(std::move(result));
		return;
	}

	const auto attempt = _attempt;
	_hostLookupId = QHostInfo::lookupHost(
		endpoint.host,
		this,
		[=](const QHostInfo &info) {
			if (!_connecting || _attempt != attempt) {
				return;
			}
			_hostLookupId = -1;
			publicEndpointResolved(result, info);
		});
	if (_hostLookupId < 0) {
		discoveryFailed(true);
	}
}

void ServerWidget::publicEndpointResolved(
		MTP::ServerDiscoveryResult result,
		const QHostInfo &info) {
	if (!_connecting) {
		return;
	}
	if (info.error() != QHostInfo::NoError) {
		discoveryFailed(true);
		return;
	}
	const auto endpoint = MTP::CheckServerSelection(result.endpoint);
	if (!MTP::IsPublicDiscoveryEndpoint(endpoint)
		|| result.policy != MTP::ServerDiscoveryPolicy::PublicHttps) {
		discoveryFailed(false);
		return;
	}
	for (const auto &address : info.addresses()) {
		if (address.protocol() != QAbstractSocket::IPv4Protocol
			&& address.protocol() != QAbstractSocket::IPv6Protocol) {
			continue;
		}
		if (MTP::IsPublicAddress(address)) {
			result.resolvedAddress = address.toString();
			commitBinding(std::move(result));
			return;
		}
	}
	discoveryFailed(false);
}

void ServerWidget::discoveryFailed(bool connectionFailure) {
	if (!_connecting) {
		return;
	}
	_connecting = false;
	++_attempt;
	_deadline->stop();
	if (_hostLookupId >= 0) {
		QHostInfo::abortHostLookup(_hostLookupId);
		_hostLookupId = -1;
	}
	if (_reply) {
		const auto reply = _reply;
		_reply = nullptr;
		disconnect(reply, nullptr, this, nullptr);
		reply->abort();
		reply->deleteLater();
	}
	if (_socket) {
		const auto socket = _socket;
		_socket = nullptr;
		disconnect(socket, nullptr, this, nullptr);
		socket->abort();
		socket->deleteLater();
	}
	_address->rawTextEdit()->setReadOnly(false);
	_continue->setDisabled(false);
	_continue->setText(tr::lng_intro_server_try_again());
	_address->setAccessibleDescription(connectionFailure
		? tr::lng_intro_server_connect_failed(tr::now)
		: tr::lng_intro_server_unsupported(tr::now));
	showStatus(
		connectionFailure
			? tr::lng_intro_server_connect_failed(tr::now)
			: tr::lng_intro_server_unsupported(tr::now),
		true);
	_address->setFocusFast();
}

void ServerWidget::cancelDiscovery() {
	if (!_connecting) {
		return;
	}
	_connecting = false;
	++_attempt;
	_deadline->stop();
	if (_hostLookupId >= 0) {
		QHostInfo::abortHostLookup(_hostLookupId);
		_hostLookupId = -1;
	}
	if (_reply) {
		const auto reply = _reply;
		_reply = nullptr;
		disconnect(reply, nullptr, this, nullptr);
		reply->abort();
		reply->deleteLater();
	}
	if (_socket) {
		const auto socket = _socket;
		_socket = nullptr;
		disconnect(socket, nullptr, this, nullptr);
		socket->abort();
		socket->deleteLater();
	}
	_address->rawTextEdit()->setReadOnly(false);
	_continue->setDisabled(false);
	_continue->setText(tr::lng_intro_server_continue());
	_address->hideError();
	clearStatus();
}

void ServerWidget::showStatus(const QString &text, bool error) {
	_status->setTextColorOverride(error
		? std::optional<QColor>(st::boxTextFgError->c)
		: std::optional<QColor>(st::windowSubTextFg->c));
	_status->setText(text);
	_status->show();
	setAccessibleDescription(text);
	announceStatus();
}

void ServerWidget::clearStatus() {
	_status->setText(QString());
	_status->hide();
	setAccessibleDescription(QString());
	_address->setAccessibleDescription(
		tr::lng_intro_server_address_ph(tr::now));
}

void ServerWidget::announceStatus() {
	auto event = QAccessibleEvent(this, QAccessible::Alert);
	QAccessible::updateAccessibility(&event);
}

void ServerWidget::commitBinding(
		const MTP::ServerDiscoveryResult &result) {
	if (result.policy != MTP::ServerDiscoveryPolicy::PublicHttps
		&& result.policy != MTP::ServerDiscoveryPolicy::LocalDirect) {
		discoveryFailed(false);
		return;
	}
	const auto expectedOrigin = (result.policy
		== MTP::ServerDiscoveryPolicy::PublicHttps)
		? MTP::PublicDiscoveryUrl(_selection)
		: (u"local:"_q + _selection.normalizedSelection);
	if (result.origin != expectedOrigin || result.dcId <= 0) {
		discoveryFailed(false);
		return;
	}
	const auto endpoint = MTP::CheckServerSelection(result.endpoint);
	const auto endpointAllowed = (result.policy
		== MTP::ServerDiscoveryPolicy::PublicHttps)
		? MTP::IsPublicDiscoveryEndpoint(endpoint)
		: (endpoint && endpoint.policy == result.policy);
	if (!endpointAllowed
		|| !result.key.valid()) {
		discoveryFailed(false);
		return;
	}
	const auto connectionHost = result.resolvedAddress.isEmpty()
		? endpoint.host
		: result.resolvedAddress;
	auto connectionAddress = QHostAddress();
	const auto connectionIsLiteral = connectionAddress.setAddress(
		connectionHost);
	const auto connectionEndpoint = MTP::CheckServerSelection(
		connectionIsLiteral
			? AddressWithPort(connectionAddress, endpoint.operationalPort)
			: connectionHost + u":"_q
				+ QString::number(endpoint.operationalPort));
	const auto connectionSafe = (result.policy
		== MTP::ServerDiscoveryPolicy::PublicHttps)
		? (connectionIsLiteral && MTP::IsPublicAddress(connectionAddress))
		: (connectionEndpoint
			&& connectionEndpoint.policy
				== MTP::ServerDiscoveryPolicy::LocalDirect);
	if (!connectionSafe) {
		discoveryFailed(false);
		return;
	}
	_deadline->stop();
	if (account().sessionExists()
		|| account().mtp().dcOptions().hasCustomServer()) {
		// A concurrent authorization or binding won the race. The existing
		// account remains immutable and this candidate is discarded.
		discoveryFailed(false);
		return;
	}
	const auto key = std::make_shared<MTP::details::RSAPublicKey>(result.key);
	const auto server = MTP::CustomServer{
		.dcId = result.dcId,
		.ip = connectionEndpoint.host.toStdString(),
		.port = endpoint.operationalPort,
		.ipv6 = connectionEndpoint.ipv6,
		.key = key,
		.serverSelection = _selection.normalizedSelection.toStdString(),
		.discoveryPolicy = result.policy,
		.discoveryOrigin = result.origin.toStdString(),
	};
	const auto previousOptions = account().mtp().dcOptions().serialize();
	const auto previousWasBlocked = account().mtp().dcOptions().blocked();
	if (!MTP::CommitServerEnrollment(
		[&] {
			return account().mtp().dcOptions().setCustomServer(server);
		},
		[&] {
			return account().local().writeMtpConfig(true);
		},
		[&] {
			account().mtp().resume();
		},
		[&] {
			if (previousWasBlocked) {
				account().mtp().dcOptions().constructBlocked();
			} else if (!account().mtp().dcOptions().constructFromSerialized(
				previousOptions)) {
				account().mtp().dcOptions().constructBlocked();
			}
		})) {
		_connecting = false;
		++_attempt;
		_deadline->stop();
		_readOnly = false;
		_addressLabel->show();
		_address->show();
		_status->show();
		_continue->show();
		_address->rawTextEdit()->setReadOnly(false);
		_continue->setDisabled(false);
		_continue->setText(tr::lng_intro_server_try_again());
		showStatus(tr::lng_intro_server_save_failed(tr::now), true);
		_address->setAccessibleDescription(
			tr::lng_intro_server_save_failed(tr::now));
		_address->setFocusFast();
		return;
	}

	_connecting = false;
	getData()->serverEndpoint = result.endpoint;
	switchToBound();
	goNext<UsernameWidget>();
}

} // namespace details
} // namespace Intro
