/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_server_discovery.h"

#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QTcpSocket>

#include <utility>

namespace Intro {
namespace details {
namespace {

constexpr auto kMaxDiscoveryBody = 16 * 1024;

} // namespace

ServerWidgetDiscovery::ServerWidgetDiscovery(QObject *parent)
: QObject(parent) {
}

bool ServerDiscoveryFlow::start(
		const MTP::ServerSelectionCheck &selection,
		Callbacks callbacks) {
	cancel();
	_callbacks = std::move(callbacks);
	if (!selection.valid()) {
		const auto failed = std::move(_callbacks.failed);
		_callbacks = {};
		if (failed) {
			failed(false);
		}
		return false;
	}
	auto *start = (selection.policy == MTP::ServerDiscoveryPolicy::PublicHttps)
		? &_callbacks.publicHttps
		: (selection.policy == MTP::ServerDiscoveryPolicy::LocalDirect)
		? &_callbacks.localDirect
		: nullptr;
	if (!start || !*start) {
		const auto failed = std::move(_callbacks.failed);
		_callbacks = {};
		if (failed) {
			failed(false);
		}
		return false;
	}
	_active = true;
	const auto callback = *start;
	callback();
	return true;
}

bool ServerDiscoveryFlow::discoveryFailed(bool connectionFailure) {
	if (!_active) {
		return false;
	}
	_active = false;
	auto failed = std::move(_callbacks.failed);
	_callbacks = {};
	if (failed) {
		failed(connectionFailure);
	}
	return true;
}

void ServerDiscoveryFlow::finish() {
	_active = false;
	_callbacks = {};
}

void ServerDiscoveryFlow::cancel() {
	finish();
}

ServerWidgetDiscovery::~ServerWidgetDiscovery() {
	cancel();
}

bool SubmitServerSelection(
		const QString &value,
		const std::function<void(MTP::ServerSelectionStatus)> &rejected,
		const std::function<void(const MTP::ServerSelectionCheck &)> &accepted) {
	const auto selection = MTP::CheckServerSelection(value);
	if (!selection) {
		if (rejected) {
			rejected(selection.status);
		}
		return false;
	}
	if (!accepted) {
		return false;
	}
	accepted(selection);
	return true;
}

ServerWidgetDiscovery::Attempt ServerWidgetDiscovery::acquireAttempt() const {
	auto token = MTP::ServerDiscoveryAttempt::Acquire();
	if (token) {
		return { .token = std::move(token) };
	}
	return {
		.fieldEditable = true,
		.retryable = true,
	};
}

void ServerWidgetDiscovery::start(
		const MTP::ServerSelectionCheck &selection,
		const QByteArray &nonce,
		const QList<QHostAddress> &addresses,
		Callbacks callbacks) {
	cancel();
	_selection = selection;
	_nonce = nonce;
	_request = MTP::BuildLocalDiscoveryRequest(_nonce);
	_addresses = addresses;
	_nextAddress = 0;
	_writeOffset = 0;
	_writeClosed = false;
	_callbacks = std::move(callbacks);
	_running = selection.valid()
		&& selection.policy == MTP::ServerDiscoveryPolicy::LocalDirect
		&& !_request.isEmpty()
		&& !_addresses.isEmpty();
	if (!_running) {
		auto callback = std::move(_callbacks.failed);
		_callbacks = {};
		if (callback) {
			callback(true);
		}
		return;
	}
	startNextAddress();
}

void ServerWidgetDiscovery::cancel() {
	_running = false;
	_callbacks = {};
	stopSocket();
}

bool ServerWidgetDiscovery::timeout() {
	if (!_running) {
		return false;
	}
	if (!_response.isEmpty()) {
		fail(false);
		return false;
	}
	if (_nextAddress >= _addresses.size()) {
		fail(true);
		return false;
	}
	startNextAddress();
	return _running;
}

void ServerWidgetDiscovery::startNextAddress() {
	if (!_running) {
		return;
	}
	stopSocket();
	if (_nextAddress >= _addresses.size()) {
		fail(true);
		return;
	}
	_response.clear();
	_writeOffset = 0;
	_writeClosed = false;
	_socket = new QTcpSocket(this);
	_socket->setProxy(QNetworkProxy::NoProxy);
	const auto socket = _socket;
	QObject::connect(socket, &QTcpSocket::connected, this, [=] {
		if (_running && _socket == socket) {
			sendRequest();
		}
	});
	QObject::connect(socket, &QTcpSocket::bytesWritten, this, [=](qint64) {
		if (_running && _socket == socket) {
			sendRequest();
		}
	});
	QObject::connect(socket, &QTcpSocket::readyRead, this, [=] {
		if (_running && _socket == socket) {
			readyRead();
		}
	});
	QObject::connect(
		socket,
		&QTcpSocket::errorOccurred,
		this,
		[=](QAbstractSocket::SocketError error) {
			if (!_running
				|| _socket != socket
				|| error == QAbstractSocket::RemoteHostClosedError) {
				return;
			}
			if (_response.isEmpty()) {
				startNextAddress();
			} else {
				fail(false);
			}
		});
	QObject::connect(socket, &QTcpSocket::disconnected, this, [=] {
		if (!_running || _socket != socket) {
			return;
		}
		_response += socket->readAll();
		if (_response.size() > kMaxDiscoveryBody) {
			fail(false);
			return;
		}
		if (_response.isEmpty()) {
			startNextAddress();
			return;
		}
		if (!MTP::IsCompleteLocalDiscoveryResponse(_response)) {
			fail(false);
			return;
		}
		finish(MTP::ParseLocalDiscoveryResponse(
			_selection,
			_nonce,
			_response));
	});
	if (_callbacks.candidateStarted) {
		_callbacks.candidateStarted();
	}
	if (!MTP::StartNextLocalDiscoverySocket(
			*socket,
			_selection,
			_addresses,
			_nextAddress)) {
		fail(true);
	}
}

void ServerWidgetDiscovery::sendRequest() {
	if (!_running || !_socket || _writeClosed) {
		return;
	}
	if (!MTP::SendLocalDiscoveryRequest(
			*_socket,
			_request,
			_writeOffset,
			_writeClosed)) {
		startNextAddress();
	}
}

void ServerWidgetDiscovery::readyRead() {
	if (!_running || !_socket) {
		return;
	}
	_response += _socket->readAll();
	if (_response.size() > kMaxDiscoveryBody) {
		fail(false);
	}
}

void ServerWidgetDiscovery::fail(bool connectionFailure) {
	if (!_running) {
		return;
	}
	_running = false;
	stopSocket();
	auto callback = std::move(_callbacks.failed);
	_callbacks = {};
	if (callback) {
		callback(connectionFailure);
	}
}

void ServerWidgetDiscovery::finish(MTP::ServerDiscoveryResult result) {
	if (!_running) {
		return;
	}
	if (!result) {
		fail(false);
		return;
	}
	if (_socket) {
		const auto peer = _socket->peerAddress();
		if (!peer.isNull()) {
			result.resolvedAddress = peer.toString();
		}
	}
	_running = false;
	stopSocket();
	auto callback = std::move(_callbacks.finished);
	_callbacks = {};
	if (callback) {
		callback(std::move(result));
	}
}

void ServerWidgetDiscovery::stopSocket() {
	if (!_socket) {
		return;
	}
	const auto socket = std::exchange(_socket, nullptr);
	QObject::disconnect(socket, nullptr, this, nullptr);
	socket->abort();
	socket->deleteLater();
}

} // namespace details
} // namespace Intro
