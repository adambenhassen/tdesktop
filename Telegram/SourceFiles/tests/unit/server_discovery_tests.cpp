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
	const auto der = TestKey().getSubjectPublicKeyInfo();
	auto response = QByteArray("telegramd-key-r1", 16) + nonce;
	AppendBigEndian(response, quint32(6 + der.size()));
	AppendBigEndian(response, quint32(2));
	AppendBigEndian(response, quint16(der.size()));
	response += QByteArray(
		reinterpret_cast<const char *>(der.data()),
		int(der.size()));

	const auto result = ParseLocalDiscoveryResponse(
		selection,
		nonce,
		response);
	CHECK(result.valid());
	CHECK_EQ(result.endpoint, selection.normalizedSelection);
	CHECK_EQ(result.dcId, 2);
	CHECK(result.key.valid());

	response.append('\0');
	const auto trailing = ParseLocalDiscoveryResponse(
		selection,
		nonce,
		response);
	CHECK(trailing.status == ServerDiscoveryResponseStatus::BadFrame);
}

TEST_CASE(DiscoveryJsonRejectsMalformedResponse) {
	const auto selection = CheckServerSelection(u"server.example.com"_q);
	const auto result = ParsePublicDiscoveryResponse(
		selection,
		QByteArray("{}"));
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
