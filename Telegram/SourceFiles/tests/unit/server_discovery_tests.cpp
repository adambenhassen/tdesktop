/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "mtproto/mtproto_server_discovery.h"

#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QUrl>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QTcpSocket>

#if defined Q_OS_WIN
#include <winsock2.h>
#else
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

[[nodiscard]] QByteArray PublicResponse(const QString &endpoint) {
	const auto key = TestKey();
	const auto der = key.getSubjectPublicKeyInfo();
	return QJsonDocument(QJsonObject{
		{ u"version"_q, 1 },
		{ u"mtproto"_q, QJsonObject{
			{ u"endpoint"_q, endpoint },
			{ u"dc_id"_q, 2 },
			{ u"rsa_spki"_q, QString::fromLatin1(QByteArray(
				reinterpret_cast<const char *>(der.data()),
				int(der.size())).toBase64()) }
		} }
	}).toJson(QJsonDocument::Compact);
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

TEST_CASE(EveryIpLiteralUsesLocalPreflight) {
	const auto result = CheckServerSelection(u"203.0.113.10:443"_q);
	CHECK(result.valid());
	CHECK(result.policy == ServerDiscoveryPolicy::LocalDirect);

	const auto global = CheckServerSelection(u"8.8.8.8:443"_q);
	CHECK(global.valid());
	CHECK(global.policy == ServerDiscoveryPolicy::LocalDirect);
	CHECK(IsPublicAddress(QHostAddress(u"8.8.8.8"_q)));
	CHECK(!IsPublicAddress(QHostAddress(u"203.0.113.10"_q)));
	CHECK(!IsPublicAddress(QHostAddress(u"10.0.0.1"_q)));
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

TEST_CASE(PublicDiscoveryRequestsDoNotUseCookies) {
	QNetworkRequest request(QUrl(
		u"https://example.com/.well-known/telegramd/client"_q));
	ConfigurePublicDiscoveryRequest(request);
	CHECK(request.attribute(QNetworkRequest::CookieLoadControlAttribute).toInt()
		== int(QNetworkRequest::Manual));
	CHECK(request.attribute(QNetworkRequest::CookieSaveControlAttribute).toInt()
		== int(QNetworkRequest::Manual));
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
