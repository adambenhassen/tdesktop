/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_server_discovery.h"

#include <QtCore/QSocketNotifier>
#include <QtNetwork/QNetworkInterface>

#include <cstring>

#if defined Q_OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <utility>

namespace Intro {
namespace details {
namespace {

constexpr auto kMaxDiscoveryBody = 16 * 1024;
constexpr auto kInvalidNativeSocket = qintptr(-1);
#if defined Q_OS_WIN
using NativeSocket = SOCKET;
#else
using NativeSocket = int;
#endif

[[nodiscard]] int LastSocketError() {
#if defined Q_OS_WIN
	return WSAGetLastError();
#else
	return errno;
#endif
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

[[nodiscard]] bool IsConnectPending(int error) {
#if defined Q_OS_WIN
	return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
	return error == EINPROGRESS
		|| error == EINTR
		|| IsWouldBlockSocketError(error);
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

void CloseNativeSocket(qintptr descriptor) {
	if (descriptor == kInvalidNativeSocket) {
		return;
	}
#if defined Q_OS_WIN
	::closesocket(static_cast<SOCKET>(descriptor));
#else
	::close(static_cast<int>(descriptor));
#endif
}

[[nodiscard]] bool SetNativeSocketNonBlocking(qintptr descriptor) {
#if defined Q_OS_WIN
	u_long mode = 1;
	return ::ioctlsocket(
		static_cast<SOCKET>(descriptor),
		FIONBIO,
		&mode) == 0;
#else
	const auto socket = static_cast<int>(descriptor);
	const auto flags = ::fcntl(socket, F_GETFL, 0);
	return flags >= 0 && ::fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

[[nodiscard]] qintptr OpenNativeSocket(
		const QHostAddress &address,
		quint16 port,
		bool &connecting,
		int &error) {
#if defined Q_OS_WIN
	struct Winsock {
		Winsock() {
			WSADATA data = {};
			ready = (WSAStartup(MAKEWORD(2, 2), &data) == 0);
		}
		~Winsock() {
			if (ready) {
				WSACleanup();
			}
		}
		bool ready = false;
	};
	static const Winsock winsock;
	if (!winsock.ready) {
		error = WSANOTINITIALISED;
		return kInvalidNativeSocket;
	}
#endif
	sockaddr_storage target = {};
	int length = 0;
	if (address.protocol() == QAbstractSocket::IPv4Protocol) {
		auto &ipv4 = reinterpret_cast<sockaddr_in &>(target);
		ipv4.sin_family = AF_INET;
		ipv4.sin_port = htons(port);
		ipv4.sin_addr.s_addr = htonl(address.toIPv4Address());
		length = sizeof(ipv4);
	} else if (address.protocol() == QAbstractSocket::IPv6Protocol) {
		auto &ipv6 = reinterpret_cast<sockaddr_in6 &>(target);
		ipv6.sin6_family = AF_INET6;
		ipv6.sin6_port = htons(port);
		const auto bytes = address.toIPv6Address();
		std::memcpy(&ipv6.sin6_addr, bytes.c, sizeof(bytes.c));
		const auto scope = address.scopeId();
		if (!scope.isEmpty()) {
			auto validNumber = false;
			ipv6.sin6_scope_id = scope.toUInt(&validNumber);
			if (!validNumber) {
				ipv6.sin6_scope_id = QNetworkInterface::interfaceFromName(
					scope).index();
			}
		}
		length = sizeof(ipv6);
	} else {
		return kInvalidNativeSocket;
	}
	const auto family = address.protocol() == QAbstractSocket::IPv4Protocol
		? AF_INET
		: AF_INET6;
#if defined Q_OS_WIN
	const auto socket = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (socket == INVALID_SOCKET) {
		error = LastSocketError();
		return kInvalidNativeSocket;
	}
#else
	const auto socket = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (socket < 0) {
		error = LastSocketError();
		return kInvalidNativeSocket;
	}
#if defined Q_OS_DARWIN
	const auto noSigpipe = 1;
	if (::setsockopt(
			socket,
			SOL_SOCKET,
			SO_NOSIGPIPE,
			&noSigpipe,
			sizeof(noSigpipe)) != 0) {
		error = LastSocketError();
		CloseNativeSocket(socket);
		return kInvalidNativeSocket;
	}
#endif
#endif
	if (!SetNativeSocketNonBlocking(qintptr(socket))) {
		error = LastSocketError();
		CloseNativeSocket(qintptr(socket));
		return kInvalidNativeSocket;
	}
	if (::connect(
			socket,
			reinterpret_cast<const sockaddr *>(&target),
			length) == 0) {
		connecting = false;
		return qintptr(socket);
	}
	error = LastSocketError();
	if (IsConnectPending(error)) {
		connecting = true;
		return qintptr(socket);
	}
	CloseNativeSocket(qintptr(socket));
	return kInvalidNativeSocket;
}

[[nodiscard]] bool NativeSocketConnected(qintptr descriptor, int &error) {
	auto result = 0;
#if defined Q_OS_WIN
	auto length = int(sizeof(result));
#else
	auto length = socklen_t(sizeof(result));
#endif
	if (::getsockopt(
			static_cast<NativeSocket>(descriptor),
			SOL_SOCKET,
			SO_ERROR,
			reinterpret_cast<char *>(&result),
			&length) != 0) {
		error = LastSocketError();
		return false;
	}
	error = result;
	return result == 0;
}

[[nodiscard]] qint64 SendNativeSocket(
		qintptr descriptor,
		const char *data,
		int size,
		int &error) {
#if defined Q_OS_WIN
	const auto result = ::send(static_cast<SOCKET>(descriptor), data, size, 0);
	if (result == SOCKET_ERROR) {
#else
	const auto result = ::send(
		static_cast<int>(descriptor),
		data,
		size,
#if defined Q_OS_LINUX
		MSG_NOSIGNAL
#else
		0
#endif
	);
	if (result < 0) {
#endif
		error = LastSocketError();
		return -1;
	}
	return result;
}

[[nodiscard]] bool ShutdownNativeSocketWrite(qintptr descriptor, int &error) {
#if defined Q_OS_WIN
	const auto result = ::shutdown(static_cast<SOCKET>(descriptor), SD_SEND);
#else
	const auto result = ::shutdown(static_cast<int>(descriptor), SHUT_WR);
#endif
	if (result != 0) {
		error = LastSocketError();
		return false;
	}
	return true;
}

[[nodiscard]] qint64 ReceiveNativeSocket(
		qintptr descriptor,
		char *buffer,
		int size,
		int &error) {
#if defined Q_OS_WIN
	const auto result = ::recv(static_cast<SOCKET>(descriptor), buffer, size, 0);
	if (result == SOCKET_ERROR) {
#else
	const auto result = ::recv(static_cast<int>(descriptor), buffer, size, 0);
	if (result < 0) {
#endif
		error = LastSocketError();
		return -1;
	}
	return result;
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
		&& _selection.explicitPort
		&& _selection.operationalPort > 0
		&& _selection.operationalPort <= 65535
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
	_response.clear();
	_writeOffset = 0;
	_writeClosed = false;
	_resolvedAddress = QHostAddress();
	while (_nextAddress < _addresses.size()) {
		const auto address = _addresses.at(_nextAddress++);
		if (address.isNull()
			|| (address.protocol() != QAbstractSocket::IPv4Protocol
				&& address.protocol() != QAbstractSocket::IPv6Protocol)) {
			continue;
		}
		if (_callbacks.candidateStarted) {
			_callbacks.candidateStarted();
			if (!_running) {
				return;
			}
		}
		auto error = 0;
		_nativeReadDescriptor = OpenNativeSocket(
			address,
			quint16(_selection.operationalPort),
			_connecting,
			error);
		if (_nativeReadDescriptor == kInvalidNativeSocket) {
			LOG(("Server discovery socket error(%1): %2")
				.arg(error)
				.arg(NativeSocketErrorString(error)));
			continue;
		}
		_resolvedAddress = address;
		const auto readNotifier = _nativeReadNotifier = new QSocketNotifier(
			_nativeReadDescriptor,
			QSocketNotifier::Read,
			this);
		readNotifier->setEnabled(!_connecting);
		QObject::connect(
			readNotifier,
			&QSocketNotifier::activated,
			this,
			[=](QSocketDescriptor, QSocketNotifier::Type) {
				if (_nativeReadNotifier == readNotifier) {
					nativeReadyRead();
				}
			});
		const auto writeNotifier = _nativeWriteNotifier = new QSocketNotifier(
			_nativeReadDescriptor,
			QSocketNotifier::Write,
			this);
		QObject::connect(
			writeNotifier,
			&QSocketNotifier::activated,
			this,
			[=](QSocketDescriptor, QSocketNotifier::Type) {
				if (_nativeWriteNotifier != writeNotifier) {
					return;
				}
				if (_connecting) {
					auto error = 0;
					if (!NativeSocketConnected(_nativeReadDescriptor, error)) {
						LOG(("Server discovery socket error(%1): %2")
							.arg(error)
							.arg(NativeSocketErrorString(error)));
						startNextAddress();
						return;
					}
					_connecting = false;
					_nativeReadNotifier->setEnabled(true);
				}
				sendRequest();
			});
		if (!_connecting) {
			sendRequest();
		}
		return;
	}
	fail(true);
}

void ServerWidgetDiscovery::sendRequest() {
	if (!_running || _connecting || _writeClosed
		|| _nativeReadDescriptor == kInvalidNativeSocket) {
		return;
	}
	while (_writeOffset < _request.size()) {
		auto error = 0;
		const auto sent = SendNativeSocket(
			_nativeReadDescriptor,
			_request.constData() + _writeOffset,
			_request.size() - _writeOffset,
			error);
		if (sent > 0) {
			_writeOffset += int(sent);
			continue;
		}
		if (sent < 0 && IsInterruptedSocketError(error)) {
			continue;
		}
		if (sent < 0 && IsWouldBlockSocketError(error)) {
			return;
		}
		LOG(("Server discovery socket error(%1): %2")
			.arg(error)
			.arg(NativeSocketErrorString(error)));
		startNextAddress();
		return;
	}
	auto error = 0;
	if (!ShutdownNativeSocketWrite(_nativeReadDescriptor, error)) {
		LOG(("Server discovery socket error(%1): %2")
			.arg(error)
			.arg(NativeSocketErrorString(error)));
		startNextAddress();
		return;
	}
	_writeClosed = true;
	_nativeWriteNotifier->setEnabled(false);
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
		LOG(("Server discovery socket error(%1): %2, response-bytes=%3")
			.arg(error)
			.arg(NativeSocketErrorString(error))
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
	if (_nativeWriteNotifier) {
		const auto notifier = std::exchange(_nativeWriteNotifier, nullptr);
		notifier->setEnabled(false);
		QObject::disconnect(notifier, nullptr, this, nullptr);
		notifier->deleteLater();
	}
	CloseNativeSocket(std::exchange(
		_nativeReadDescriptor,
		kInvalidNativeSocket));
	_connecting = false;
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
	if (!_resolvedAddress.isNull()) {
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
}

} // namespace details
} // namespace Intro
