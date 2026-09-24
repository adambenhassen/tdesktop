/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "intro/intro_server_discovery.h"
#include "mtproto/mtproto_server_discovery.h"

#include <QtCore/QEventLoop>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QList>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QTcpSocket>

#if defined Q_OS_WIN
#include <winsock2.h>
#else
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include <utility>

namespace {

using namespace MTP;

const char kRsa2048Spki[] = "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n\
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n\
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n\
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n\
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n\
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n\
-----END RSA PUBLIC KEY-----";

[[nodiscard]] details::RSAPublicKey TestKey() {
	return details::RSAPublicKey(bytes::make_span(
		kRsa2048Spki,
		sizeof(kRsa2048Spki) - 1));
}

void AppendBigEndian(QByteArray &target, quint32 value) {
	target.append(char(value >> 24));
	target.append(char(value >> 16));
	target.append(char(value >> 8));
	target.append(char(value));
}

void AppendBigEndian(QByteArray &target, quint16 value) {
	target.append(char(value >> 8));
	target.append(char(value));
}

[[nodiscard]] QByteArray LocalResponse(const QByteArray &nonce) {
	const auto der = TestKey().getSubjectPublicKeyInfo();
	auto response = QByteArray("telegramd-key-r1", 16) + nonce;
	AppendBigEndian(response, quint32(6 + der.size()));
	AppendBigEndian(response, quint32(2));
	AppendBigEndian(response, quint16(der.size()));
	response += QByteArray(
		reinterpret_cast<const char *>(der.data()),
		int(der.size()));
	return response;
}

#if defined Q_OS_WIN
using NativeTestSocket = SOCKET;
#else
using NativeTestSocket = int;
#endif

[[nodiscard]] NativeTestSocket AsNativeTestSocket(qintptr descriptor) {
	return static_cast<NativeTestSocket>(descriptor);
}

[[nodiscard]] NativeTestSocket AcceptNativeTestSocket(qintptr descriptor) {
	return ::accept(
		AsNativeTestSocket(descriptor),
		nullptr,
		nullptr);
}

[[nodiscard]] bool SetNativeTestNonBlocking(qintptr descriptor) {
#if defined Q_OS_WIN
	u_long mode = 1;
	return ::ioctlsocket(
		AsNativeTestSocket(descriptor),
		FIONBIO,
		&mode) == 0;
#else
	const auto socket = AsNativeTestSocket(descriptor);
	const auto flags = ::fcntl(socket, F_GETFL, 0);
	return flags >= 0 && ::fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

void CloseNativeTestSocket(NativeTestSocket socket) {
#if defined Q_OS_WIN
	::closesocket(socket);
#else
	::close(socket);
#endif
}

[[nodiscard]] bool SetNativeTestReceiveTimeout(NativeTestSocket socket) {
#if defined Q_OS_WIN
	DWORD timeout = 1000;
	return ::setsockopt(
		socket,
		SOL_SOCKET,
		SO_RCVTIMEO,
		reinterpret_cast<const char *>(&timeout),
		int(sizeof(timeout))) == 0;
#else
	const timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
	return ::setsockopt(
		socket,
		SOL_SOCKET,
		SO_RCVTIMEO,
		&timeout,
		socklen_t(sizeof(timeout))) == 0;
#endif
}

[[nodiscard]] qint64 ReceiveNativeTestSocket(
		NativeTestSocket socket,
		char *buffer,
		int size) {
#if defined Q_OS_WIN
	return ::recv(socket, buffer, size, 0);
#else
	return ::recv(socket, buffer, size_t(size), 0);
#endif
}

[[nodiscard]] qint64 SendNativeTestSocket(
		NativeTestSocket socket,
		const char *buffer,
		int size) {
#if defined Q_OS_WIN
	return ::send(socket, buffer, size, 0);
#else
	return ::send(socket, buffer, size_t(size), 0);
#endif
}

[[nodiscard]] QByteArray PublicResponse(
		const QString &endpoint,
		const QByteArray &encodedKey) {
	return QJsonDocument(QJsonObject{
		{ u"version"_q, 1 },
		{ u"mtproto"_q, QJsonObject{
			{ u"endpoint"_q, endpoint },
			{ u"dc_id"_q, 2 },
			{ u"rsa_spki"_q, QString::fromLatin1(encodedKey) }
		} }
	}).toJson(QJsonDocument::Compact);
}

[[nodiscard]] QByteArray PublicResponse(const QString &endpoint) {
	const auto der = TestKey().getSubjectPublicKeyInfo();
	return PublicResponse(endpoint, QByteArray(
		reinterpret_cast<const char *>(der.data()),
		int(der.size())).toBase64());
}

TEST_CASE(PublicSelectionDefaultsToHttps) {
	const auto result = CheckServerSelection(u" Example.COM. "_q);
	CHECK(result.valid());
	CHECK(result.policy == ServerDiscoveryPolicy::PublicHttps);
	CHECK_EQ(result.host, u"example.com"_q);
	CHECK_EQ(result.normalizedSelection, u"example.com"_q);
	CHECK_EQ(result.operationalPort, 443);
}

TEST_CASE(LocalSelectionRequiresExplicitPort) {
	const auto result = CheckServerSelection(u"localhost"_q);
	CHECK(result.status == ServerSelectionStatus::NoPort);

	const auto withPort = CheckServerSelection(u"localhost:443"_q);
	CHECK(withPort.valid());
	CHECK(withPort.policy == ServerDiscoveryPolicy::LocalDirect);
	CHECK_EQ(withPort.normalizedSelection, u"localhost:443"_q);
}

TEST_CASE(LocalLiteralAllowListCoversNetworkBoundaries) {
	const auto allowed = {
		std::pair{ u"10.0.0.1:2443"_q, true },
		std::pair{ u"172.16.0.1:2443"_q, true },
		std::pair{ u"192.168.0.1:2443"_q, true },
		std::pair{ u"100.64.0.1:2443"_q, true },
		std::pair{ u"127.0.0.1:2443"_q, true },
		std::pair{ u"[::1]:2443"_q, true },
		std::pair{ u"[fc00::1]:2443"_q, true },
		std::pair{ u"[fe80::1]:2443"_q, true },
		std::pair{ u"11.0.0.1:2443"_q, false },
		std::pair{ u"172.32.0.1:2443"_q, false },
		std::pair{ u"192.169.0.1:2443"_q, false },
		std::pair{ u"100.128.0.1:2443"_q, false },
		std::pair{ u"128.0.0.1:2443"_q, false },
		std::pair{ u"[::2]:2443"_q, false },
		std::pair{ u"[fe00::1]:2443"_q, false },
		std::pair{ u"[fec0::1]:2443"_q, false },
		std::pair{ u"8.8.8.8:2443"_q, false },
		std::pair{ u"169.254.1.1:2443"_q, false },
		std::pair{ u"198.18.0.1:2443"_q, false },
		std::pair{ u"203.0.113.1:2443"_q, false },
		std::pair{ u"[64:ff9b::1]:2443"_q, false },
	};
	for (const auto &[value, shouldBeAllowed] : allowed) {
		const auto selection = CheckServerSelection(value);
		CHECK_EQ(selection.valid(), shouldBeAllowed);
		if (shouldBeAllowed) {
			CHECK(selection.policy == ServerDiscoveryPolicy::LocalDirect);
		} else {
			CHECK(selection.status == ServerSelectionStatus::PublicIpLiteral);
		}
	}
}

TEST_CASE(MappedIpv6LiteralUsesEmbeddedIpv4Policy) {
	const auto privateAddress = CheckServerSelection(
		u"[::ffff:192.168.1.5]:2443"_q);
	CHECK(privateAddress.valid());
	CHECK(privateAddress.policy == ServerDiscoveryPolicy::LocalDirect);

	const auto publicAddress = CheckServerSelection(
		u"[::ffff:8.8.8.8]:2443"_q);
	CHECK(publicAddress.status == ServerSelectionStatus::PublicIpLiteral);
}

TEST_CASE(RefusedIpLiteralDoesNotStartLocalConnection) {
	QTcpServer server;
	CHECK(server.listen(QHostAddress::LocalHost));
	if (!server.isListening()) {
		return;
	}
	const auto selection = CheckServerSelection(
		u"8.8.8.8:"_q + QString::number(server.serverPort()));
	Intro::details::ServerWidgetDiscovery discovery(nullptr);
	auto candidates = 0;
	auto failed = false;
	discovery.start(
		selection,
		QByteArray(32, '\0'),
		{ QHostAddress(QHostAddress::LocalHost) },
		{
			.failed = [&](bool) { failed = true; },
			.candidateStarted = [&] { ++candidates; },
		});
	CHECK(!discovery.running());
	CHECK(failed);
	CHECK_EQ(candidates, 0);
	CHECK(!server.waitForNewConnection(100));
	CHECK_EQ(server.pendingConnectionCount(), 0);
}

TEST_CASE(LocalLiteralRequiresPortWhileDottedAddressKeepsDomainRoute) {
	CHECK(CheckServerSelection(u"10.0.0.1"_q).status
		== ServerSelectionStatus::NoPort);
	CHECK(CheckServerSelection(u"8.8.8.8"_q).status
		== ServerSelectionStatus::PublicIpLiteral);
	CHECK(CheckServerSelection(u"[::1]"_q).status
		== ServerSelectionStatus::NoPort);
	CHECK(CheckServerSelection(u"[2001:4860::8888]"_q).status
		== ServerSelectionStatus::PublicIpLiteral);
	const auto dotted = CheckServerSelection(u"8.8.8.8.:2443"_q);
	CHECK(dotted.valid());
	CHECK(dotted.policy == ServerDiscoveryPolicy::PublicHttps);
}

TEST_CASE(DomainAndLocalNameRoutesRemainUnchanged) {
	for (const auto &domain : {
		u"telegram-server.tailaa4918.ts.net"_q,
		u"example.com"_q,
	}) {
		const auto selection = CheckServerSelection(domain);
		CHECK(selection.valid());
		CHECK(selection.policy == ServerDiscoveryPolicy::PublicHttps);
	}
	for (const auto &local : {
		u"localhost:2443"_q,
		u"server.local:2443"_q,
		u"server.home.arpa:2443"_q,
		u"intranet:2443"_q,
	}) {
		const auto selection = CheckServerSelection(local);
		CHECK(selection.valid());
		CHECK(selection.policy == ServerDiscoveryPolicy::LocalDirect);
	}
}

TEST_CASE(PublicDiscoveryRejectsSpecialPurposeIpv6Addresses) {
	const auto selection = CheckServerSelection(u"server.example.com"_q);
	const auto special = {
		u"64:ff9b:1::1"_q,
		u"100:0:0:1::1"_q,
		u"3fff::1"_q,
		u"5f00::1"_q,
	};
	for (const auto &text : special) {
		const auto address = QHostAddress(text);
		CHECK(!IsPublicAddress(address));

		const auto result = ParsePublicDiscoveryResponse(
			selection,
			PublicResponse(u"["_q + text + u"]:443"_q));
		CHECK(result.status == ServerDiscoveryResponseStatus::UnsafeEndpoint);

		QHostInfo info;
		info.setAddresses({ address });
		for (const auto &answer : info.addresses()) {
			CHECK(!IsPublicAddress(answer));
		}
	}
}

TEST_CASE(PublicDiscoveryNormalizesIpv4MappedAddresses) {
	CHECK(IsPublicAddress(QHostAddress(u"::ffff:8.8.8.8"_q)));
	CHECK(!IsPublicAddress(QHostAddress(u"::ffff:10.0.0.1"_q)));
}

TEST_CASE(SelectionRejectsNonRoutableIpLiterals) {
	CHECK(CheckServerSelection(u"0.0.0.0:443"_q).status
		== ServerSelectionStatus::InvalidSpecialAddress);
	CHECK(CheckServerSelection(u"255.255.255.255:443"_q).status
		== ServerSelectionStatus::InvalidSpecialAddress);
	CHECK(CheckServerSelection(u"[::]:443"_q).status
		== ServerSelectionStatus::InvalidSpecialAddress);
	CHECK(CheckServerSelection(u"[ff02::1]:443"_q).status
		== ServerSelectionStatus::InvalidSpecialAddress);
}

TEST_CASE(SelectionRejectsNonCanonicalIpLiterals) {
	CHECK(CheckServerSelection(u"[2001:0DB8::1]:443"_q).status
		== ServerSelectionStatus::BadHost);
}

TEST_CASE(PublicSelectionRetainsPortConstraint) {
	const auto result = CheckServerSelection(u"server.example.com:8443"_q);
	CHECK(result.valid());
	CHECK(result.policy == ServerDiscoveryPolicy::PublicHttps);
	CHECK_EQ(result.requestedPort, 8443);
	CHECK_EQ(result.operationalPort, 8443);
}

TEST_CASE(UnicodeHostIsCanonicalized) {
	const auto result = CheckServerSelection(u"bücher.example"_q);
	CHECK(result.valid());
	CHECK_EQ(result.host, u"xn--bcher-kva.example"_q);
}

TEST_CASE(LocalRequestHasExactFrame) {
	const auto nonce = QByteArray(32, '\x01');
	const auto request = BuildLocalDiscoveryRequest(nonce);
	CHECK_EQ(request.size(), 48);
	CHECK_EQ(request.left(16), QByteArray("telegramd-key-v1", 16));
	CHECK_EQ(request.mid(16), nonce);
}

TEST_CASE(LocalRequestRejectsWrongNonceSize) {
	CHECK(BuildLocalDiscoveryRequest(QByteArray(31, '\x01')).isEmpty());
}

TEST_CASE(LocalResponseRoundTripsOnlyAfterEof) {
	const auto selection = CheckServerSelection(u"127.0.0.1:2443"_q);
	const auto nonce = QByteArray(32, '\x02');
	const auto response = LocalResponse(nonce);

	const auto result = ParseLocalDiscoveryResponse(
		selection,
		nonce,
		response);
	CHECK(result.valid());
	CHECK_EQ(result.endpoint, selection.normalizedSelection);
	CHECK_EQ(result.dcId, 2);
	CHECK(result.key.valid());

	auto trailingResponse = response;
	trailingResponse.append('\0');
	const auto trailing = ParseLocalDiscoveryResponse(
		selection,
		nonce,
		trailingResponse);
	CHECK(trailing.status == ServerDiscoveryResponseStatus::BadFrame);
}

TEST_CASE(LocalResponseTransportCompletesAtDisconnect) {
	const auto selection = CheckServerSelection(u"127.0.0.1:2443"_q);
	const auto nonce = QByteArray(32, '\x03');
	const auto response = LocalResponse(nonce);
	QByteArray received;
	QTcpServer server;
	CHECK(server.listen(QHostAddress::LocalHost));
	QTcpSocket client;
	client.connectToHost(server.serverAddress(), server.serverPort());
	CHECK(client.waitForConnected(1000));
	CHECK(server.waitForNewConnection(1000));
	const auto peer = server.nextPendingConnection();
	CHECK(peer != nullptr);
	if (!peer) {
		return;
	}

	peer->write(response.left(response.size() - 1));
	CHECK(peer->waitForBytesWritten(1000));
	CHECK(client.waitForReadyRead(1000));
	received += client.readAll();
	CHECK(!IsCompleteLocalDiscoveryResponse(received));

	peer->write(response.right(1));
	CHECK(peer->waitForBytesWritten(1000));
	peer->disconnectFromHost();
	while (client.state() != QAbstractSocket::UnconnectedState
		&& client.waitForReadyRead(1000)) {
		received += client.readAll();
	}
	received += client.readAll();
	CHECK(client.state() == QAbstractSocket::UnconnectedState);
	CHECK(IsCompleteLocalDiscoveryResponse(received));
	CHECK(ParseLocalDiscoveryResponse(selection, nonce, received).valid());

	peer->deleteLater();
}

TEST_CASE(LocalDiscoveryStartsSocketForLiteralAndLocalName) {
	QTcpServer server;
	CHECK(server.listen(QHostAddress::LocalHost));
	if (!server.isListening()) {
		return;
	}

	const auto port = server.serverPort();
	for (const auto &host : { u"127.0.0.1"_q, u"localhost"_q }) {
		const auto selection = CheckServerSelection(
			host + u":"_q + QString::number(port));
		CHECK(selection.valid());
		if (!selection) {
			continue;
		}

		QTcpSocket client;
		auto connected = false;
		auto address = QHostAddress();
		if (address.setAddress(selection.host)) {
			CHECK(StartLocalDiscoverySocket(client, selection, address));
			connected = client.waitForConnected(1000);
		} else {
			const auto resolved = QHostInfo::fromName(selection.host);
			CHECK(resolved.error() == QHostInfo::NoError);
			CHECK(!resolved.addresses().isEmpty());
			if (resolved.error() != QHostInfo::NoError) {
				continue;
			}
			for (const auto &resolvedAddress : resolved.addresses()) {
				if (!StartLocalDiscoverySocket(
						client,
						selection,
						resolvedAddress)) {
					continue;
				}
				if (client.waitForConnected(1000)) {
					connected = true;
					break;
				}
				client.abort();
			}
		}
		CHECK(connected);
		if (!connected) {
			continue;
		}
		CHECK(server.waitForNewConnection(1000));
		const auto peer = server.nextPendingConnection();
		CHECK(peer != nullptr);
		if (peer) {
			peer->deleteLater();
		}
		client.disconnectFromHost();
		client.waitForDisconnected(1000);
	}
}

TEST_CASE(LocalDiscoveryRequestHalfClosesBeforeResponse) {
	QByteArray received;
	QTcpServer server;
	CHECK(server.listen(QHostAddress::LocalHost));
	if (!server.isListening()) {
		return;
	}
	server.pauseAccepting();

	const auto selection = CheckServerSelection(
		u"127.0.0.1:"_q + QString::number(server.serverPort()));
	const auto nonce = QByteArray(32, '\x04');
	const auto request = BuildLocalDiscoveryRequest(nonce);
	const auto response = LocalResponse(nonce);
	QTcpSocket client;
	CHECK(StartLocalDiscoverySocket(
		client,
		selection,
		server.serverAddress()));
	CHECK(client.waitForConnected(1000));
	const auto peer = AcceptNativeTestSocket(server.socketDescriptor());
#if defined Q_OS_WIN
	const auto invalidPeer = INVALID_SOCKET;
#else
	const auto invalidPeer = -1;
#endif
	CHECK(peer != invalidPeer);
	if (peer == invalidPeer) {
		return;
	}

	CHECK(SetNativeTestReceiveTimeout(peer));
	auto writeOffset = 0;
	auto writeClosed = false;
	auto writeSucceeded = true;
	while (!writeClosed && writeSucceeded) {
		writeSucceeded = SendLocalDiscoveryRequest(
			client,
			request,
			writeOffset,
			writeClosed);
		CHECK(writeSucceeded);
		if (!writeClosed) {
			const auto bytesWritten = client.waitForBytesWritten(1000);
			CHECK(bytesWritten);
			if (!bytesWritten) {
				break;
			}
		}
	}
	CHECK(writeClosed);
	CHECK_EQ(writeOffset, request.size());

	QByteArray peerRequest;
	auto peerSawEof = false;
	while (peerRequest.size() <= request.size()) {
		char buffer[256];
		const auto read = ReceiveNativeTestSocket(
			peer,
			buffer,
			int(sizeof(buffer)));
		if (read > 0) {
			peerRequest.append(buffer, int(read));
			continue;
		}
		if (read == 0) {
			peerSawEof = true;
		}
		if (read <= 0) {
			break;
		}
	}
	CHECK(peerSawEof);
	CHECK_EQ(peerRequest, request);
	if (!peerSawEof || peerRequest != request) {
		CloseNativeTestSocket(peer);
		return;
	}

	auto responseOffset = 0;
	while (responseOffset < response.size()) {
		const auto written = SendNativeTestSocket(
			peer,
			response.constData() + responseOffset,
			response.size() - responseOffset);
		CHECK(written > 0);
		if (written <= 0) {
			break;
		}
		responseOffset += int(written);
	}
	CHECK_EQ(responseOffset, response.size());
	CloseNativeTestSocket(peer);
	while (client.state() != QAbstractSocket::UnconnectedState
		&& client.waitForReadyRead(1000)) {
		received += client.readAll();
	}
	received += client.readAll();
	CHECK(IsCompleteLocalDiscoveryResponse(received));
	CHECK(ParseLocalDiscoveryResponse(selection, nonce, received).valid());
}

TEST_CASE(LocalDiscoveryFailsOverToLaterResolvedAddress) {
	QTcpServer server;
	CHECK(server.listen(QHostAddress::LocalHost));
	if (!server.isListening()) {
		return;
	}
	server.pauseAccepting();

	const auto selection = CheckServerSelection(
		u"localhost:"_q + QString::number(server.serverPort()));
	CHECK(selection.valid());
	if (!selection) {
		return;
	}

	const auto nonce = QByteArray(32, '\x05');
	const auto request = BuildLocalDiscoveryRequest(nonce);
	const auto response = LocalResponse(nonce);
	const QList<QHostAddress> addresses{
		QHostAddress(u"127.0.0.2"_q),
		server.serverAddress(),
	};
	QTcpSocket client;
	auto nextAddress = 0;
	CHECK(StartNextLocalDiscoverySocket(
		client,
		selection,
		addresses,
		nextAddress));
	CHECK_EQ(nextAddress, 1);
	CHECK(!client.waitForConnected(1000));
	client.abort();

	CHECK(StartNextLocalDiscoverySocket(
		client,
		selection,
		addresses,
		nextAddress));
	CHECK_EQ(nextAddress, 2);
	const auto connected = client.waitForConnected(1000);
	CHECK(connected);
	if (!connected) {
		return;
	}
#if defined Q_OS_WIN
	const auto invalidPeer = INVALID_SOCKET;
#else
	const auto invalidPeer = -1;
#endif
	const auto peer = AcceptNativeTestSocket(server.socketDescriptor());
	CHECK(peer != invalidPeer);
	if (peer == invalidPeer) {
		return;
	}
	const auto hasReceiveTimeout = SetNativeTestReceiveTimeout(peer);
	CHECK(hasReceiveTimeout);
	if (!hasReceiveTimeout) {
		CloseNativeTestSocket(peer);
		return;
	}

	auto writeOffset = 0;
	auto writeClosed = false;
	while (!writeClosed) {
		CHECK(SendLocalDiscoveryRequest(
			client,
			request,
			writeOffset,
			writeClosed));
		if (!writeClosed) {
			CHECK(client.waitForBytesWritten(1000));
		}
	}
	CHECK_EQ(writeOffset, request.size());

	QByteArray receivedRequest;
	auto peerSawEof = false;
	while (receivedRequest.size() <= request.size()) {
		char buffer[256];
		const auto read = ReceiveNativeTestSocket(
			peer,
			buffer,
			int(sizeof(buffer)));
		if (read > 0) {
			receivedRequest.append(buffer, int(read));
			continue;
		}
		if (read == 0) {
			peerSawEof = true;
		}
		break;
	}
	CHECK(peerSawEof);
	CHECK_EQ(receivedRequest, request);
	if (!peerSawEof || receivedRequest != request) {
		CloseNativeTestSocket(peer);
		return;
	}
	auto responseOffset = 0;
	while (responseOffset < response.size()) {
		const auto written = SendNativeTestSocket(
			peer,
			response.constData() + responseOffset,
			response.size() - responseOffset);
		CHECK(written > 0);
		if (written <= 0) {
			break;
		}
		responseOffset += int(written);
	}
	CHECK_EQ(responseOffset, response.size());
	CloseNativeTestSocket(peer);
	QByteArray receivedResponse;
	while (client.state() != QAbstractSocket::UnconnectedState
		&& client.waitForReadyRead(1000)) {
		receivedResponse += client.readAll();
	}
	receivedResponse += client.readAll();
	CHECK(IsCompleteLocalDiscoveryResponse(receivedResponse));
	CHECK(ParseLocalDiscoveryResponse(
		selection,
		nonce,
		receivedResponse).valid());
}

TEST_CASE(ServerWidgetDiscoveryAdvancesAcrossLocalFailures) {
	using Intro::details::ServerWidgetDiscovery;

	QTcpServer server;
	CHECK(server.listen(QHostAddress::LocalHost));
	if (!server.isListening()) {
		return;
	}
	server.pauseAccepting();
	const auto nonBlocking = SetNativeTestNonBlocking(
		server.socketDescriptor());
	CHECK(nonBlocking);
	if (!nonBlocking) {
		return;
	}

	const auto selection = CheckServerSelection(
		u"localhost:"_q + QString::number(server.serverPort()));
	CHECK(selection.valid());
	if (!selection) {
		return;
	}
	const auto nonce = QByteArray(32, '\x06');
	const auto request = BuildLocalDiscoveryRequest(nonce);
	const auto response = LocalResponse(nonce);
	const QList<QHostAddress> addresses{
		QHostAddress(u"127.0.0.2"_q),
		server.serverAddress(),
		server.serverAddress(),
		server.serverAddress(),
	};

	QObject owner;
	ServerWidgetDiscovery discovery(&owner);
	QEventLoop loop;
	QTimer poll;
	QTimer::singleShot(5000, &loop, &QEventLoop::quit);

	auto started = 0;
	auto accepted = 0;
	auto finished = false;
	auto failed = false;
	QObject::connect(&poll, &QTimer::timeout, &owner, [&] {
#if defined Q_OS_WIN
		const auto invalidPeer = INVALID_SOCKET;
#else
		const auto invalidPeer = -1;
#endif
		const auto peer = AcceptNativeTestSocket(server.socketDescriptor());
		if (peer == invalidPeer) {
			return;
		}
		++accepted;
		if (accepted == 1) {
			CloseNativeTestSocket(peer);
			return;
		}
		if (accepted == 2) {
			CHECK(discovery.timeout());
			CloseNativeTestSocket(peer);
			return;
		}
		if (accepted != 3) {
			CloseNativeTestSocket(peer);
			return;
		}

		CHECK(SetNativeTestReceiveTimeout(peer));
		QByteArray receivedRequest;
		auto peerSawEof = false;
		while (receivedRequest.size() <= request.size()) {
			char buffer[256];
			const auto read = ReceiveNativeTestSocket(
				peer,
				buffer,
				int(sizeof(buffer)));
			if (read > 0) {
				receivedRequest.append(buffer, int(read));
				continue;
			}
			if (read == 0) {
				peerSawEof = true;
			}
			break;
		}
		CHECK(peerSawEof);
		CHECK_EQ(receivedRequest, request);
		auto responseOffset = 0;
		while (responseOffset < response.size()) {
			const auto written = SendNativeTestSocket(
				peer,
				response.constData() + responseOffset,
				response.size() - responseOffset);
			CHECK(written > 0);
			if (written <= 0) {
				break;
			}
			responseOffset += int(written);
		}
		CHECK_EQ(responseOffset, response.size());
		CloseNativeTestSocket(peer);
	});
	poll.start(1);

	discovery.start(
		selection,
		nonce,
		addresses,
		{
			.finished = [&](ServerDiscoveryResult result) {
				finished = true;
				CHECK(result.valid());
				CHECK_EQ(
					result.resolvedAddress,
					server.serverAddress().toString());
				loop.quit();
			},
			.failed = [&](bool) {
				failed = true;
				loop.quit();
			},
			.candidateStarted = [&] {
				++started;
			},
		});
	loop.exec();
	poll.stop();

	CHECK_EQ(started, 4);
	CHECK_EQ(accepted, 3);
	CHECK(finished);
	CHECK(!failed);
}

TEST_CASE(ServerWidgetDiscoveryRejectsPartialResponseOnTimeout) {
	using Intro::details::ServerWidgetDiscovery;

	QTcpServer server;
	CHECK(server.listen(QHostAddress::LocalHost));
	if (!server.isListening()) {
		return;
	}
	server.pauseAccepting();
	const auto nonBlocking = SetNativeTestNonBlocking(
		server.socketDescriptor());
	CHECK(nonBlocking);
	if (!nonBlocking) {
		return;
	}

	const auto selection = CheckServerSelection(
		u"localhost:"_q + QString::number(server.serverPort()));
	CHECK(selection.valid());
	if (!selection) {
		return;
	}
	const auto nonce = QByteArray(32, '\x07');

	QObject owner;
	ServerWidgetDiscovery discovery(&owner);
	QEventLoop loop;
	QTimer poll;
	QTimer::singleShot(5000, &loop, &QEventLoop::quit);

#if defined Q_OS_WIN
	const auto invalidPeer = INVALID_SOCKET;
#else
	const auto invalidPeer = -1;
#endif
	NativeTestSocket peer = invalidPeer;
	const auto partialResponse = QByteArrayLiteral("telegramd-key-r1");
	auto started = 0;
	auto accepted = 0;
	auto timeoutCalled = false;
	auto finished = false;
	auto failed = false;
	QObject::connect(&poll, &QTimer::timeout, &owner, [&] {
		const auto nextPeer = AcceptNativeTestSocket(server.socketDescriptor());
		if (nextPeer == invalidPeer) {
			return;
		}
		++accepted;
		if (peer == invalidPeer) {
			peer = nextPeer;
			CHECK_EQ(
				SendNativeTestSocket(
					peer,
					partialResponse.constData(),
					partialResponse.size()),
				partialResponse.size());
			QTimer::singleShot(50, &owner, [&] {
				timeoutCalled = true;
				CHECK(!discovery.timeout());
			});
		} else {
			CloseNativeTestSocket(nextPeer);
		}
	});
	poll.start(1);

	discovery.start(
		selection,
		nonce,
		{ server.serverAddress(), server.serverAddress() },
		{
			.finished = [&](ServerDiscoveryResult) {
				finished = true;
				loop.quit();
			},
			.failed = [&](bool connectionFailure) {
				failed = true;
				CHECK(!connectionFailure);
				loop.quit();
			},
			.candidateStarted = [&] {
				++started;
			},
		});
	loop.exec();
	poll.stop();
	if (peer != invalidPeer) {
		CloseNativeTestSocket(peer);
	}

	CHECK(timeoutCalled);
	CHECK(failed);
	CHECK(!finished);
	CHECK_EQ(started, 1);
	CHECK_EQ(accepted, 1);
	CHECK(!discovery.running());
}

TEST_CASE(ServerWidgetDiscoveryLimitIsRetryable) {
	using Intro::details::ServerWidgetDiscovery;

	QObject owner;
	ServerWidgetDiscovery discovery(&owner);
	auto first = discovery.acquireAttempt();
	auto second = discovery.acquireAttempt();
	auto third = discovery.acquireAttempt();
	auto fourth = discovery.acquireAttempt();
	CHECK(first.token.has_value());
	CHECK(second.token.has_value());
	CHECK(third.token.has_value());
	CHECK(fourth.token.has_value());

	const auto fifth = discovery.acquireAttempt();
	CHECK(!fifth.token.has_value());
	CHECK(fifth.fieldEditable);
	CHECK(fifth.retryable);
}

TEST_CASE(PublicDiscoveryRequestsUseRestrictedPolicy) {
	QNetworkRequest request(QUrl(
		u"https://example.com/.well-known/telegramd/client"_q));
	ConfigurePublicDiscoveryRequest(request);
	CHECK(request.attribute(QNetworkRequest::CookieLoadControlAttribute).toInt()
		== int(QNetworkRequest::Manual));
	CHECK(request.attribute(QNetworkRequest::CookieSaveControlAttribute).toInt()
		== int(QNetworkRequest::Manual));
	CHECK(request.attribute(QNetworkRequest::CacheLoadControlAttribute).toInt()
		== int(QNetworkRequest::AlwaysNetwork));
	CHECK(!request.attribute(QNetworkRequest::CacheSaveControlAttribute).toBool());
	CHECK(request.attribute(QNetworkRequest::RedirectPolicyAttribute).toInt()
		== int(QNetworkRequest::ManualRedirectPolicy));
	auto hasUserAgent = false;
	for (const auto &header : request.rawHeaderList()) {
		if (header.compare("User-Agent", Qt::CaseInsensitive) == 0) {
			hasUserAgent = true;
			break;
		}
	}
	CHECK(hasUserAgent);
	const auto userAgent = request.rawHeader(QByteArray("User-Agent"));
	CHECK_EQ(userAgent, QByteArrayLiteral("-"));
}

TEST_CASE(DiscoveryAttemptsAreLimitedAndReleased) {
	auto first = ServerDiscoveryAttempt::Acquire();
	auto second = ServerDiscoveryAttempt::Acquire();
	auto third = ServerDiscoveryAttempt::Acquire();
	auto fourth = ServerDiscoveryAttempt::Acquire();
	CHECK(first.has_value());
	CHECK(second.has_value());
	CHECK(third.has_value());
	CHECK(fourth.has_value());
	CHECK(!ServerDiscoveryAttempt::Acquire().has_value());

	first.reset();
	CHECK(ServerDiscoveryAttempt::Acquire().has_value());
}

TEST_CASE(DiscoveryAttemptMoveReleasesExactlyOnce) {
	auto first = ServerDiscoveryAttempt::Acquire();
	auto second = ServerDiscoveryAttempt::Acquire();
	auto third = ServerDiscoveryAttempt::Acquire();
	auto fourth = ServerDiscoveryAttempt::Acquire();
	CHECK(first.has_value());
	CHECK(second.has_value());
	CHECK(third.has_value());
	CHECK(fourth.has_value());
	{
		auto moved = std::move(*first);
		first.reset();
		CHECK(!ServerDiscoveryAttempt::Acquire().has_value());
	}
	CHECK(ServerDiscoveryAttempt::Acquire().has_value());
}

TEST_CASE(DiscoveryJsonRejectsMalformedResponse) {
	const auto selection = CheckServerSelection(u"server.example.com"_q);
	const auto result = ParsePublicDiscoveryResponse(
		selection,
		QByteArray("{"));
	CHECK(result.status == ServerDiscoveryResponseStatus::InvalidJson);
}

TEST_CASE(DiscoveryJsonRejectsDuplicateKeys) {
	const auto result = ParsePublicDiscoveryResponse(
		CheckServerSelection(u"server.example.com"_q),
		QByteArray(R"({"version":1,"version":1,"mtproto":{}})"));
	CHECK(result.status == ServerDiscoveryResponseStatus::InvalidJson);
}

TEST_CASE(DiscoveryJsonRejectsNonCanonicalBase64) {
	const auto der = TestKey().getSubjectPublicKeyInfo();
	auto encoded = QByteArray(
		reinterpret_cast<const char *>(der.data()),
		int(der.size())).toBase64();
	encoded.append('\n');
	const auto result = ParsePublicDiscoveryResponse(
		CheckServerSelection(u"server.example.com"_q),
		PublicResponse(u"mtproto.example.com:443"_q, encoded));
	CHECK(result.status == ServerDiscoveryResponseStatus::InvalidKey);
}

TEST_CASE(DiscoveryJsonRejectsInvalidBase64) {
	const auto der = TestKey().getSubjectPublicKeyInfo();
	auto encoded = QByteArray(
		reinterpret_cast<const char *>(der.data()),
		int(der.size())).toBase64();
	encoded[0] = '!';
	const auto result = ParsePublicDiscoveryResponse(
		CheckServerSelection(u"server.example.com"_q),
		PublicResponse(u"mtproto.example.com:443"_q, encoded));
	CHECK(result.status == ServerDiscoveryResponseStatus::InvalidKey);
}

TEST_CASE(DiscoveryJsonRejectsNonRsaSubjectPublicKeyInfo) {
	const auto der = QByteArray::fromHex(
		"3059301306072a8648ce3d020106082a8648ce3d030107"
		"0342000497fc873893ed223585e805a4ea3a5e92a6913eb5"
		"3654ea97c5cdc19529d807998e4189fc64fe396edb4fef47"
		"57f525a5e81d82ba2d1bc56ede4d0951a8888e24");
	const auto result = ParsePublicDiscoveryResponse(
		CheckServerSelection(u"server.example.com"_q),
		PublicResponse(
			u"mtproto.example.com:443"_q,
			der.toBase64()));
	CHECK(result.status == ServerDiscoveryResponseStatus::InvalidKey);
}

TEST_CASE(DiscoveryJsonRejectsWrongRsaModulusSize) {
	const auto der = QByteArray::fromHex(
		"30819f300d06092a864886f70d010101050003818d00"
		"30818902818100b712cf541b031bf5ee4bc37c954eed62"
		"2e2e4f1fc2719de13c689e2d51088a351c5c33d450355d"
		"4e55e7818a45c4a90df7c84ab803beae6bc882a8c7035c"
		"bb5b1790d9a4a771e2a25ea0a8789d7f35a005d62db43b"
		"ae7a541f1b2e2f5a61da4b39b120ab03ccaece8dfcd343"
		"c3de8a12782400ee9c1c6f990ffbd5c19d38b68b020301"
		"0001");
	const auto result = ParsePublicDiscoveryResponse(
		CheckServerSelection(u"server.example.com"_q),
		PublicResponse(
			u"mtproto.example.com:443"_q,
			der.toBase64()));
	CHECK(result.status == ServerDiscoveryResponseStatus::InvalidKey);
}

TEST_CASE(SelectionRejectsOversizedHost) {
	const auto result = CheckServerSelection(QString(1025, QChar('a')));
	CHECK(result.status == ServerSelectionStatus::HostTooLong);
}

TEST_CASE(DiscoveryJsonPreservesVerifiedBinding) {
	const auto selection = CheckServerSelection(u"server.example.com"_q);
	const auto key = TestKey();
	CHECK(key.valid());
	const auto der = key.getSubjectPublicKeyInfo();
	const auto json = QJsonDocument(QJsonObject{
		{ u"version"_q, 1 },
		{ u"future"_q, true },
		{ u"mtproto"_q, QJsonObject{
			{ u"endpoint"_q, u"mtproto.example.com:443"_q },
			{ u"dc_id"_q, 2 },
			{ u"future"_q, u"ignored"_q },
			{ u"rsa_spki"_q, QString::fromLatin1(QByteArray(
				reinterpret_cast<const char *>(der.data()),
				int(der.size())).toBase64()) }
		} }
	}).toJson(QJsonDocument::Compact);
	const auto result = ParsePublicDiscoveryResponse(selection, json);
	CHECK(result.valid());
	CHECK_EQ(result.endpoint, u"mtproto.example.com:443"_q);
	CHECK_EQ(result.dcId, 2);
	CHECK(result.policy == ServerDiscoveryPolicy::PublicHttps);
}

TEST_CASE(DiscoveryJsonRejectsConstrainedPortConflict) {
	const auto selection = CheckServerSelection(u"server.example.com:8443"_q);
	const auto key = TestKey();
	const auto der = key.getSubjectPublicKeyInfo();
	const auto json = QJsonDocument(QJsonObject{
		{ u"version"_q, 1 },
		{ u"mtproto"_q, QJsonObject{
			{ u"endpoint"_q, u"mtproto.example.com:443"_q },
			{ u"dc_id"_q, 2 },
			{ u"rsa_spki"_q, QString::fromLatin1(QByteArray(
				reinterpret_cast<const char *>(der.data()),
				int(der.size())).toBase64()) }
		} }
	}).toJson(QJsonDocument::Compact);
	const auto result = ParsePublicDiscoveryResponse(selection, json);
	CHECK(result.status == ServerDiscoveryResponseStatus::EndpointMismatch);
}

TEST_CASE(DiscoveryJsonAcceptsPublicIpEndpoint) {
	const auto selection = CheckServerSelection(u"server.example.com"_q);
	const auto key = TestKey();
	const auto der = key.getSubjectPublicKeyInfo();
	const auto json = QJsonDocument(QJsonObject{
		{ u"version"_q, 1 },
		{ u"mtproto"_q, QJsonObject{
			{ u"endpoint"_q, u"8.8.8.8:443"_q },
			{ u"dc_id"_q, 2 },
			{ u"rsa_spki"_q, QString::fromLatin1(QByteArray(
				reinterpret_cast<const char *>(der.data()),
				int(der.size())).toBase64()) }
		} }
	}).toJson(QJsonDocument::Compact);
	const auto result = ParsePublicDiscoveryResponse(selection, json);
	CHECK(result.valid());
	CHECK_EQ(result.endpoint, u"8.8.8.8:443"_q);
}

TEST_CASE(DiscoveryJsonRequiresAnExplicitEndpointPort) {
	const auto selection = CheckServerSelection(u"server.example.com"_q);
	const auto key = TestKey();
	const auto der = key.getSubjectPublicKeyInfo();
	const auto json = QJsonDocument(QJsonObject{
		{ u"version"_q, 1 },
		{ u"mtproto"_q, QJsonObject{
			{ u"endpoint"_q, u"mtproto.example.com"_q },
			{ u"dc_id"_q, 2 },
			{ u"rsa_spki"_q, QString::fromLatin1(QByteArray(
				reinterpret_cast<const char *>(der.data()),
				int(der.size())).toBase64()) }
		} }
	}).toJson(QJsonDocument::Compact);
	const auto result = ParsePublicDiscoveryResponse(selection, json);
	CHECK(result.status == ServerDiscoveryResponseStatus::UnsafeEndpoint);
}

} // namespace
