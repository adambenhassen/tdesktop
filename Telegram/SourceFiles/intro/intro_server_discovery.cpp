/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_server_discovery.h"

#include <QtCore/QSocketNotifier>

#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QTcpSocket>

#if defined Q_OS_WIN
#include <winsock2.h>
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <utility>

namespace Intro {
namespace details {
namespace {

constexpr auto kMaxDiscoveryBody = 16 * 1024;
constexpr auto kInvalidNativeSocket = qintptr(-1);

[[nodiscard]] qintptr DuplicateNativeSocket(qintptr descriptor, int &error) {
#if defined Q_OS_WIN
	WSAPROTOCOL_INFO info = {};
	if (WSADuplicateSocket(
		static_cast<SOCKET>(descriptor),
		GetCurrentProcessId(),
		&info) != 0) {
		error = WSAGetLastError();
		return kInvalidNativeSocket;
	}
	const auto duplicated = WSASocket(
		FROM_PROTOCOL_INFO,
		FROM_PROTOCOL_INFO,
		FROM_PROTOCOL_INFO,
		&info,
		0,
		WSA_FLAG_OVERLAPPED);
	if (duplicated == INVALID_SOCKET) {
		error = WSAGetLastError();
		return kInvalidNativeSocket;
	}
	return qintptr(duplicated);
#else
	const auto duplicated = ::dup(static_cast<int>(descriptor));
	if (duplicated < 0) {
		error = errno;
		return kInvalidNativeSocket;
	}
	return qintptr(duplicated);
#endif
}

void CloseNativeSocket(qintptr descriptor) {
	if (descriptor == kInvalidNativeSocket) {
		return;
	}
#if defined Q_OS_WIN
	closesocket(static_cast<SOCKET>(descriptor));
#else
	::close(static_cast<int>(descriptor));
#endif
}

[[nodiscard]] bool ShutdownNativeSocketWrite(
		qintptr descriptor,
		int &error) {
#if defined Q_OS_WIN
	if (::shutdown(static_cast<SOCKET>(descriptor), SD_SEND) != 0) {
		error = WSAGetLastError();
		return false;
	}
#else
	if (::shutdown(static_cast<int>(descriptor), SHUT_WR) != 0) {
		error = errno;
		return false;
	}
#endif
	return true;
}

[[nodiscard]] qint64 ReceiveNativeSocket(
		qintptr descriptor,
		char *buffer,
		qint64 size,
		int &error) {
#if defined Q_OS_WIN
	const auto result = ::recv(
		static_cast<SOCKET>(descriptor),
		buffer,
		int(size),
		0);
	if (result == SOCKET_ERROR) {
		error = WSAGetLastError();
		return -1;
	}
#else
	const auto result = ::recv(
		static_cast<int>(descriptor),
		buffer,
		size_t(size),
		0);
	if (result < 0) {
		error = errno;
		return -1;
	}
#endif
	return qint64(result);
}

[[nodiscard]] bool IsInterruptedSocketError(int error) {
#if defined Q_OS_WIN
	return error == WSAEINTR;
#else
	return error == EINTR;
#endif
}

[[nodiscard]] bool IsWouldBlockSocketError(int error) {
#if defined Q_OS_WIN
	return error == WSAEWOULDBLOCK;
#else
	return error == EAGAIN || error == EWOULDBLOCK;
#endif
}

[[nodiscard]] QString NativeSocketErrorString(int error) {
#if defined Q_OS_WIN
	LPSTR message = nullptr;
	const auto size = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER
			| FORMAT_MESSAGE_FROM_SYSTEM
			| FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		DWORD(error),
		0,
		reinterpret_cast<LPSTR>(&message),
		0,
		nullptr);
	if (!size) {
		return QString::number(error);
	}
	auto result = QString::fromLocal8Bit(message, int(size)).trimmed();
	LocalFree(message);
	return result;
#else
	return QString::fromLocal8Bit(std::strerror(error));
#endif
}

} // namespace

ServerWidgetDiscovery::ServerWidgetDiscovery(QObject *parent)
: QObject(parent) {
}

ServerWidgetDiscovery::~ServerWidgetDiscovery() {
	cancel();
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
	_resolvedAddress = QHostAddress();
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
	_resolvedAddress = QHostAddress();
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
			LOG(("Server discovery errorOccurred(%1): %2, half-close=%3, response-bytes=%4")
				.arg(int(error))
				.arg(socket->errorString())
				.arg(_writeClosed ? 1 : 0)
				.arg(_response.size()));
			if (!_running
				|| _socket != socket
				|| error == QAbstractSocket::RemoteHostClosedError) {
				return;
			}
			if (_writeClosed) {
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
		LOG(("Server discovery disconnected, half-close=%1, response-bytes=%2")
			.arg(_writeClosed ? 1 : 0)
			.arg(_response.size()));
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
	const auto socket = _socket;
	if (!MTP::SendLocalDiscoveryRequest(
		*socket,
		_request,
		_writeOffset)) {
		startNextAddress();
		return;
	}
	if (_writeOffset != _request.size() || socket->bytesToWrite() > 0) {
		return;
	}
	_response += socket->readAll();
	if (_response.size() > kMaxDiscoveryBody) {
		fail(false);
		return;
	}
	auto error = 0;
	const auto descriptor = DuplicateNativeSocket(
		socket->socketDescriptor(),
		error);
	if (descriptor == kInvalidNativeSocket) {
		LOG(("Server discovery errorOccurred(%1): %2, half-close=%3, response-bytes=%4")
			.arg(error)
			.arg(NativeSocketErrorString(error))
			.arg(_writeClosed ? 1 : 0)
			.arg(_response.size()));
		startNextAddress();
		return;
	}
	const auto peer = socket->peerAddress();
	if (!peer.isNull()) {
		_resolvedAddress = peer;
	}
	const auto qtSocket = std::exchange(_socket, nullptr);
	QObject::disconnect(qtSocket, nullptr, this, nullptr);
	qtSocket->disconnectFromHost();
	qtSocket->deleteLater();
	_nativeReadDescriptor = descriptor;
	if (!ShutdownNativeSocketWrite(_nativeReadDescriptor, error)) {
		LOG(("Server discovery errorOccurred(%1): %2, half-close=%3, response-bytes=%4")
			.arg(error)
			.arg(NativeSocketErrorString(error))
			.arg(_writeClosed ? 1 : 0)
			.arg(_response.size()));
		startNextAddress();
		return;
	}
	_writeClosed = true;
	const auto notifier = _nativeReadNotifier = new QSocketNotifier(
		_nativeReadDescriptor,
		QSocketNotifier::Read,
		this);
	QObject::connect(
		notifier,
		&QSocketNotifier::activated,
		this,
		[=](QSocketDescriptor, QSocketNotifier::Type) {
			if (_nativeReadNotifier == notifier) {
				nativeReadyRead();
			}
		});
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

void ServerWidgetDiscovery::nativeReadyRead() {
	if (!_running || _nativeReadDescriptor == kInvalidNativeSocket) {
		return;
	}
	while (true) {
		char buffer[4096];
		auto error = 0;
		const auto received = ReceiveNativeSocket(
			_nativeReadDescriptor,
			buffer,
			int(sizeof(buffer)),
			error);
		if (received > 0) {
			_response.append(buffer, int(received));
			if (_response.size() > kMaxDiscoveryBody) {
				fail(false);
				return;
			}
			continue;
		}
		if (received == 0) {
			LOG(("Server discovery disconnected, half-close=%1, response-bytes=%2")
				.arg(_writeClosed ? 1 : 0)
				.arg(_response.size()));
			finishNativeRead();
			return;
		}
		if (IsInterruptedSocketError(error)) {
			continue;
		}
		if (IsWouldBlockSocketError(error)) {
			return;
		}
		LOG(("Server discovery errorOccurred(%1): %2, half-close=%3, response-bytes=%4")
			.arg(error)
			.arg(NativeSocketErrorString(error))
			.arg(_writeClosed ? 1 : 0)
			.arg(_response.size()));
		if (_response.isEmpty()) {
			startNextAddress();
		} else {
			fail(false);
		}
		return;
	}
}

void ServerWidgetDiscovery::finishNativeRead() {
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
}

void ServerWidgetDiscovery::closeNativeSocket() {
	if (_nativeReadNotifier) {
		const auto notifier = std::exchange(_nativeReadNotifier, nullptr);
		notifier->setEnabled(false);
		QObject::disconnect(notifier, nullptr, this, nullptr);
		notifier->deleteLater();
	}
	CloseNativeSocket(std::exchange(
		_nativeReadDescriptor,
		kInvalidNativeSocket));
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
	} else if (!_resolvedAddress.isNull()) {
		result.resolvedAddress = _resolvedAddress.toString();
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
	closeNativeSocket();
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
