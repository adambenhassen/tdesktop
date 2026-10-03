/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <iterator>
#include <thread>
#include <utility>
#include <vector>

#include "main/session_feature_support.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/connection_server_resolving.h"
#include "mtproto/mtproto_dc_options.h"
#include "mtproto/mtproto_server_enrollment.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/proxy_check.h"
#include "mtproto/session.h"
#ifdef Q_OS_UNIX
#include "tests/unit/system_resolver_fixture.h"
#endif

#include <QtCore/QByteArray>
#include <QtCore/QDataStream>
#include <QtCore/QEventLoop>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtNetwork/QHostInfo>

namespace MTP::details {
namespace {

int UnitConnectionCounter = 0;

} // namespace

using UnitConnectionFactory = Fn<ConnectionPointer(
	not_null<Instance*> instance,
	DcOptions::Variants::Protocol protocol,
	QThread *thread,
	const bytes::vector &secret,
	const ProxyData &proxy)>;

const UnitConnectionFactory *UnitConnectionFactoryInstance = nullptr;

ConnectionPointer::ConnectionPointer() = default;

ConnectionPointer::ConnectionPointer(AbstractConnection *value)
: _value(value) {
}

ConnectionPointer::ConnectionPointer(std::nullptr_t) {
}

ConnectionPointer::ConnectionPointer(ConnectionPointer &&other)
: _value(base::take(other._value)) {
}

ConnectionPointer &ConnectionPointer::operator=(ConnectionPointer &&other) {
	reset(base::take(other._value));
	return *this;
}

AbstractConnection *ConnectionPointer::get() const {
	return _value;
}

void ConnectionPointer::reset(AbstractConnection *value) {
	if (_value == value) {
		return;
	}
	delete _value;
	_value = value;
}

ConnectionPointer::operator AbstractConnection*() const {
	return get();
}

AbstractConnection *ConnectionPointer::operator->() const {
	return get();
}

AbstractConnection &ConnectionPointer::operator*() const {
	return *get();
}

ConnectionPointer::operator bool() const {
	return get() != nullptr;
}

ConnectionPointer::~ConnectionPointer() {
	reset();
}

AbstractConnection::AbstractConnection(
		QThread *thread,
		const ProxyData &proxy)
: _proxy(proxy)
, _debugId(QString::number(++UnitConnectionCounter)) {
	moveToThread(thread);
}

ConnectionPointer AbstractConnection::Create(
		not_null<Instance*> instance,
		DcOptions::Variants::Protocol protocol,
		QThread *thread,
		const bytes::vector &secret,
		const ProxyData &proxy) {
	Expects(UnitConnectionFactoryInstance != nullptr);
	return (*UnitConnectionFactoryInstance)(
		instance,
		protocol,
		thread,
		secret,
		proxy);
}

} // namespace MTP::details

namespace MTP::details {

DcOptions *UnitProxyCheckOptions = nullptr;

} // namespace MTP::details

namespace MTP {

DcId Instance::mainDcId() const {
	Expects(details::UnitProxyCheckOptions != nullptr);
	return details::UnitProxyCheckOptions->customServer().dcId;
}

DcOptions &Instance::dcOptions() const {
	Expects(details::UnitProxyCheckOptions != nullptr);
	return *details::UnitProxyCheckOptions;
}

} // namespace MTP

namespace {

using namespace MTP;

// Telegram's production public key. Its fingerprint is fixed by the
// MTProto specification — SHA1 over the TL serialisation of (n, e),
// bytes 12..20 read as a little-endian int64 — so the constant below is
// derivable from the protocol rather than from this implementation, and
// third-party MTProto libraries publish the same value. That is what
// makes it an oracle: a change to the digest's encoding (operand order,
// TL length prefix, padding, offset, endianness) moves the fingerprint
// off this number while still compiling and still looking plausible.
const char kProductionKey[] = "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n\
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n\
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n\
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n\
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n\
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n\
-----END RSA PUBLIC KEY-----";

constexpr auto kProductionKeyFingerprint = qint64(-3414540481677951611LL);

[[nodiscard]] bytes::const_span KeyBytes() {
	return bytes::make_span(kProductionKey, sizeof(kProductionKey) - 1);
}

[[nodiscard]] std::shared_ptr<details::RSAPublicKey> MakeKey() {
	return std::make_shared<details::RSAPublicKey>(KeyBytes());
}

[[nodiscard]] CustomServer MakeCustomServer() {
	return CustomServer{
		.dcId = 2,
		.ip = "10.4.1.7",
		.port = 8443,
		.key = MakeKey(),
	};
}

struct ProxyCheckObservation {
	ProxyData::Type proxyType = ProxyData::Type::None;
	QString addressPassedToChild;
	int port = 0;
	bool connected = false;
};

struct UnitHostLookupResponse {
	QList<QHostAddress> addresses;
	QHostInfo::HostInfoError error = QHostInfo::NoError;
	bool timeout = false;
};

enum class OwnerRemovalDnsResponse {
	NoErrorNoData,
	NxDomain,
	RejectedAddress,
};

class UnitHostResolver final {
public:
	MTP::details::ServerHostnameResolver resolver() {
		return {
			.lookup = [this](
					const QString &,
					QObject *,
					bool,
					Fn<void(const QHostInfo &)> callback) {
				if (_nextResponse >= _responses.size()) {
					return qint64(-1);
				}
				const auto &response = _responses[_nextResponse++];
				if (response.timeout) {
					return qint64(1);
				}
				QHostInfo info;
				info.setError(response.error);
				info.setAddresses(response.addresses);
				callback(info);
				return qint64(-1);
			},
			.abort = [this](qint64) {
				++_aborts;
			}
		};
	}

	void resolve(
			const QString &,
			bool,
			QHostInfo &info) {
		if (_nextResponse >= _responses.size()) {
			info.setError(QHostInfo::HostNotFound);
			return;
		}
		const auto &response = _responses[_nextResponse++];
		info.setError(response.error);
		info.setAddresses(response.addresses);
	}

	void add(UnitHostLookupResponse response) {
		_responses.push_back(std::move(response));
	}

	[[nodiscard]] int lookups() const {
		return _nextResponse;
	}

	[[nodiscard]] int aborts() const {
		return _aborts;
	}

private:
	std::vector<UnitHostLookupResponse> _responses;
	int _nextResponse = 0;
	int _aborts = 0;

};

void SetDefaultHostnameResolver(UnitHostResolver &resolver) {
	details::SetServerHostnameResolverTestLookup(
		[&resolver](const QString &hostname, bool ipv6, QHostInfo &info) {
			resolver.resolve(hostname, ipv6, info);
		});
}

class ProxyCheckObserver final : public details::AbstractConnection {
public:
	ProxyCheckObserver(
		QThread *thread,
		const ProxyData &proxy,
		ProxyCheckObservation *observation)
	: details::AbstractConnection(thread, proxy)
	, _observation(observation) {
	}

	details::ConnectionPointer clone(const ProxyData &) override {
		return nullptr;
	}

	crl::time pingTime() const override {
		return 0;
	}

	crl::time fullConnectTimeout() const override {
		return 0;
	}

	void sendData(mtpBuffer &&) override {
	}

	void disconnectFromServer() override {
	}

	void connectToServer(
			const QString &address,
			int port,
			const bytes::vector &,
			int16,
			bool) override {
		_observation->addressPassedToChild = address;
		_observation->port = port;
		_observation->proxyType = _proxy.type;
		_observation->connected = true;
		connected();
	}

	bool isConnected() const override {
		return _observation->connected;
	}

	int32 debugState() const override {
		return 0;
	}

	QString transport() const override {
		return u"test"_q;
	}

	QString tag() const override {
		return u"test"_q;
	}

private:
	ProxyCheckObservation *_observation = nullptr;

};

} // namespace

// The discovered key must match the fingerprint the server logs at startup,
// so client and server have to agree on this number exactly. Getting it wrong
// is invisible at compile time and shows up only as an auth-key exchange that
// never completes.
TEST_CASE(RsaPublicKeyFingerprintMatchesTheProtocol) {
	const auto key = MakeKey();
	CHECK(key->valid());
	CHECK_EQ(qint64(key->fingerprint()), kProductionKeyFingerprint);
}

// The same key rebuilt from the (n, e) byte pair that gets persisted has
// to come out with the same fingerprint, or a pinned account stops
// recognising its own server after a restart.
TEST_CASE(RsaPublicKeySurvivesTheBytePairRoundTrip) {
	const auto key = MakeKey();
	CHECK(key->valid());

	const auto restored = details::RSAPublicKey(key->getN(), key->getE());
	CHECK(restored.valid());
	CHECK_EQ(qint64(restored.fingerprint()), kProductionKeyFingerprint);
}

// The custom-server block. Endpoint identity and key bytes are written;
// the fingerprint is recomputed on load. Every field matters: without
// dcId the CDN-shadowing refusal matches nothing and the pin is
// silently ineffective.
TEST_CASE(PinnedCustomServerSurvivesSerialization) {
	auto options = DcOptions(Environment::Production);
	const auto server = MakeCustomServer();
	CHECK(options.setCustomServer(server));

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));

	CHECK(restored.hasCustomServer());
	CHECK(restored.isCustomServerPinned(server.dcId));
	CHECK(restored.refusesProductionFallback());

	const auto got = restored.customServer();
	CHECK_EQ(got.dcId, server.dcId);
	CHECK_EQ(got.ip, server.ip);
	CHECK_EQ(got.port, server.port);
	CHECK(got.key != nullptr);
	if (got.key) {
		CHECK(got.key->valid());
		CHECK_EQ(qint64(got.key->fingerprint()), kProductionKeyFingerprint);
	}
}

// Authorization state is server-scoped. A copied key-destruction state may
// only be reused when the endpoint and verified key are exactly unchanged.
TEST_CASE(AuthorizationStateCannotCrossServerPin) {
	const auto original = MakeCustomServer();
	CHECK(SameCustomServerPin(original, original));
	CHECK(!SameCustomServerPin(CustomServer(), original));

	const auto key = MakeKey();
	auto changedKey = original;
	auto n = key->getN();
	n.back() = bytes::type(
		gsl::to_integer<unsigned char>(n.back()) ^ 0x01);
	changedKey.key = std::make_shared<details::RSAPublicKey>(
		n,
		key->getE());
	CHECK(changedKey.key->valid());
	CHECK(!SameCustomServerPin(changedKey, original));

	auto changed = original;
	changed.port += 1;
	CHECK(!SameCustomServerPin(original, changed));
}

// Address-only discovery stores the normalized selection and the origin that
// authenticated it alongside the operational binding. Losing either field
// on restart would turn a verified enrollment into an unclassified legacy
// pin, so the complete metadata must survive the same encrypted config blob.
TEST_CASE(DiscoveredCustomServerMetadataSurvivesSerialization) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.serverSelection = "10.4.1.7:8443";
	server.discoveryPolicy = ServerDiscoveryPolicy::LocalDirect;
	server.discoveryOrigin = "local:10.4.1.7:8443";
	CHECK(options.setCustomServer(server));

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));

	const auto got = restored.customServer();
	CHECK_EQ(got.serverSelection, server.serverSelection);
	CHECK(got.discoveryPolicy == server.discoveryPolicy);
	CHECK_EQ(got.discoveryOrigin, server.discoveryOrigin);
}

TEST_CASE(StoredPublicLocalDirectPinLoadsButNewOneIsRefused) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.serverSelection = "10.4.1.7:8443";
	server.discoveryPolicy = ServerDiscoveryPolicy::LocalDirect;
	server.discoveryOrigin = "local:10.4.1.7:8443";
	CHECK(options.setCustomServer(server));

	auto serialized = options.serialize();
	CHECK(serialized.contains("10.4.1.7"));
	serialized.replace("10.4.1.7", "8.8.8.88");

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(serialized));
	CHECK(restored.hasCustomServer());
	CHECK(restored.refusesProductionFallback());
	const auto got = restored.customServer();
	CHECK_EQ(got.ip, "8.8.8.88");
	CHECK_EQ(got.serverSelection, "8.8.8.88:8443");
	CHECK(got.discoveryPolicy == ServerDiscoveryPolicy::LocalDirect);
	CHECK_EQ(got.discoveryOrigin, "local:8.8.8.88:8443");
	CHECK(got.key != nullptr);
	if (got.key) {
		CHECK_EQ(qint64(got.key->fingerprint()),
			qint64(kProductionKeyFingerprint));
	}

	auto fresh = DcOptions(Environment::Production);
	server.ip = "8.8.8.88";
	server.serverSelection = "8.8.8.88:8443";
	server.discoveryOrigin = "local:8.8.8.88:8443";
	CHECK(!fresh.setCustomServer(server));
}

TEST_CASE(StoredSpecialUseLocalDirectPinsRemainLoadableButNewOnesAreRefused) {
	const auto cases = {
		std::pair{ "192.168.1.1", "169.254.1.1" },
		std::pair{ "192.168.1.10", "203.0.113.10" },
	};
	for (const auto &[sourceAddress, address] : cases) {
		auto source = DcOptions(Environment::Production);
		auto server = MakeCustomServer();
		server.ip = sourceAddress;
		server.serverSelection = std::string(sourceAddress) + ":8443";
		server.discoveryPolicy = ServerDiscoveryPolicy::LocalDirect;
		server.discoveryOrigin = std::string("local:") + sourceAddress + ":8443";
		CHECK(source.setCustomServer(server));

		auto serialized = source.serialize();
		const auto serializedSize = serialized.size();
		serialized.replace(sourceAddress, address);
		CHECK_EQ(serialized.size(), serializedSize);

		auto restored = DcOptions(Environment::Production);
		CHECK(restored.constructFromSerialized(serialized));
		CHECK(restored.hasCustomServer());
		CHECK(restored.refusesProductionFallback());
		const auto got = restored.customServer();
		CHECK_EQ(got.ip, address);
		CHECK_EQ(got.serverSelection, std::string(address) + ":8443");
		CHECK_EQ(
			got.discoveryOrigin,
			std::string("local:") + address + ":8443");
		CHECK(got.discoveryPolicy == ServerDiscoveryPolicy::LocalDirect);
		CHECK(got.key != nullptr);
		if (got.key) {
			CHECK_EQ(qint64(got.key->fingerprint()),
				qint64(kProductionKeyFingerprint));
		}

		auto fresh = DcOptions(Environment::Production);
		server.ip = address;
		server.serverSelection = std::string(address) + ":8443";
		server.discoveryOrigin = std::string("local:") + address + ":8443";
		CHECK(!fresh.setCustomServer(server));
	}
}

TEST_CASE(PublicHttpsDiscoveryEnrollsWithPublicResolvedAddress) {
	const auto selection = CheckServerSelection(u"server.example.com"_q);
	const auto key = MakeKey();
	const auto der = key->getSubjectPublicKeyInfo();
	const auto encoded = QString::fromLatin1(QByteArray(
		reinterpret_cast<const char *>(der.data()),
		int(der.size())).toBase64());
	for (const auto &endpoint : {
		u"8.8.8.88:8443"_q,
		u"mtproto.example.com:8443"_q,
	}) {
		const auto json = QJsonDocument(QJsonObject{
			{ u"version"_q, 1 },
			{ u"mtproto"_q, QJsonObject{
				{ u"endpoint"_q, endpoint },
				{ u"dc_id"_q, 2 },
				{ u"rsa_spki"_q, encoded }
			} }
		}).toJson(QJsonDocument::Compact);
		auto result = ParsePublicDiscoveryResponse(selection, json);
		CHECK(result.valid());
		CHECK_EQ(result.endpoint, endpoint);
		CHECK(result.policy == ServerDiscoveryPolicy::PublicHttps);
		result.resolvedAddress = u"8.8.8.88"_q;
		const auto server = BuildCustomServerFromDiscovery(selection, result);
		CHECK(server.has_value());
		if (!server) {
			continue;
		}
		CHECK_EQ(server->ip, "8.8.8.88");
		CHECK_EQ(server->serverSelection, "server.example.com");
		CHECK(server->discoveryPolicy == ServerDiscoveryPolicy::PublicHttps);
		CHECK_EQ(
			server->discoveryOrigin,
			"https://server.example.com/.well-known/telegramd/client");

		auto options = DcOptions(Environment::Production);
		CHECK(options.setCustomServer(*server));

		auto restored = DcOptions(Environment::Production);
		CHECK(restored.constructFromSerialized(options.serialize()));
		const auto got = restored.customServer();
		CHECK_EQ(got.ip, "8.8.8.88");
		CHECK_EQ(got.port, 8443);
		CHECK(got.discoveryPolicy == ServerDiscoveryPolicy::PublicHttps);
		CHECK_EQ(got.discoveryOrigin, server->discoveryOrigin);
		CHECK(got.key != nullptr);
		if (got.key) {
			CHECK_EQ(qint64(got.key->fingerprint()),
				qint64(key->fingerprint()));
		}
	}
}

TEST_CASE(PublicHttpsSameOriginDiscoveryRetainsHostname) {
	const auto selection = CheckServerSelection(
		u"telegram-server.tailaa4918.ts.net"_q);
	const auto key = MakeKey();
	const auto der = key->getSubjectPublicKeyInfo();
	const auto json = QJsonDocument(QJsonObject{
		{ u"version"_q, 1 },
		{ u"mtproto"_q, QJsonObject{
			{ u"endpoint"_q,
				u"telegram-server.tailaa4918.ts.net:2443"_q },
			{ u"dc_id"_q, 2 },
			{ u"rsa_spki"_q, QString::fromLatin1(QByteArray(
				reinterpret_cast<const char *>(der.data()),
				int(der.size())).toBase64()) }
		} }
	}).toJson(QJsonDocument::Compact);
	auto result = ParsePublicDiscoveryResponse(selection, json);
	CHECK(result.valid());
	result.resolvedAddress = u"100.124.236.66"_q;

	const auto server = BuildCustomServerFromDiscovery(selection, result);
	CHECK(server.has_value());
	if (!server) {
		return;
	}
	CHECK_EQ(server->hostname, "telegram-server.tailaa4918.ts.net");
	CHECK(server->ip.empty());
	CHECK_EQ(server->port, 2443);
	CHECK(!server->ipv6);

	auto options = DcOptions(Environment::Production);
	CHECK(options.setCustomServer(*server));
	const auto variants = options.lookup(server->dcId, DcType::Regular, false);
	for (const auto address : {
		DcOptions::Variants::IPv4,
		DcOptions::Variants::IPv6,
	}) {
		const auto &tcp = variants.data[address][DcOptions::Variants::Tcp];
		CHECK_EQ(int(tcp.size()), 1);
		if (tcp.size() == 1) {
			CHECK_EQ(tcp.front().ip, server->hostname);
			CHECK_EQ(tcp.front().port, server->port);
		}
		CHECK(variants.data[address][DcOptions::Variants::Http].empty());
	}

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));
	const auto got = restored.customServer();
	CHECK_EQ(got.hostname, server->hostname);
	CHECK(got.ip.empty());
	CHECK_EQ(got.port, server->port);
}

TEST_CASE(HostnamePinRejectsInvalidCanonicalRestoreAndOlderVersion) {
	const auto selection = CheckServerSelection(u"server.example.com"_q);
	const auto key = MakeKey();
	const auto der = key->getSubjectPublicKeyInfo();
	auto result = ParsePublicDiscoveryResponse(
		selection,
		QJsonDocument(QJsonObject{
			{ u"version"_q, 1 },
			{ u"mtproto"_q, QJsonObject{
				{ u"endpoint"_q, u"server.example.com:2443"_q },
				{ u"dc_id"_q, 2 },
				{ u"rsa_spki"_q, QString::fromLatin1(QByteArray(
					reinterpret_cast<const char *>(der.data()),
					int(der.size())).toBase64()) }
			} }
		}).toJson(QJsonDocument::Compact));
	result.resolvedAddress = u"8.8.8.8"_q;
	const auto server = BuildCustomServerFromDiscovery(selection, result);
	CHECK(server.has_value());
	if (!server) {
		return;
	}

	auto options = DcOptions(Environment::Production);
	CHECK(options.setCustomServer(*server));
	const auto serialized = options.serialize();
	const auto hostnameOffset = serialized.lastIndexOf("server.example.com");
	CHECK(hostnameOffset >= 0);
	if (hostnameOffset < 0) {
		return;
	}
	auto invalidCanonical = serialized;
	invalidCanonical.replace(
		hostnameOffset,
		QByteArray("server.example.com").size(),
		"Server.example.com");
	auto restored = DcOptions(Environment::Production);
	CHECK(!restored.constructFromSerialized(invalidCanonical));

	auto olderVersion = serialized;
	olderVersion[0] = char(0xFF);
	olderVersion[1] = char(0xFF);
	olderVersion[2] = char(0xFF);
	olderVersion[3] = char(0xFA);
	CHECK(!restored.constructFromSerialized(olderVersion));
}

TEST_CASE(PublicMagicDnsTailnetBindingSurvivesSerialization) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.ip = "100.124.236.66";
	server.port = 2443;
	server.serverSelection = "telegram-server.tailaa4918.ts.net";
	server.discoveryPolicy = ServerDiscoveryPolicy::PublicHttps;
	server.discoveryOrigin =
		"https://telegram-server.tailaa4918.ts.net/"
		".well-known/telegramd/client";
	CHECK(options.setCustomServer(server));

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));
	CHECK(restored.hasCustomServer());
	const auto got = restored.customServer();
	CHECK_EQ(got.ip, server.ip);
	CHECK_EQ(got.port, server.port);
	CHECK_EQ(got.serverSelection, server.serverSelection);
	CHECK(got.discoveryPolicy == server.discoveryPolicy);
	CHECK_EQ(got.discoveryOrigin, server.discoveryOrigin);
	CHECK_EQ(got.dcId, server.dcId);
	CHECK(got.key != nullptr);
	CHECK(got.key->valid());
}

TEST_CASE(HistoricalLiteralBindingsRestoreUnchanged) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.ip = "100.124.236.66";
	server.port = 2443;
	server.serverSelection = "100.124.236.66:2443";
	server.discoveryPolicy = ServerDiscoveryPolicy::LocalDirect;
	server.discoveryOrigin = "local:100.124.236.66:2443";
	CHECK(options.setCustomServer(server));

	const auto serialized = options.serialize();
	const auto historicalTail = int(sizeof(qint32) * 6
		+ server.serverSelection.size()
		+ server.discoveryOrigin.size());
	const auto customBlockEnd = serialized.size() - historicalTail;
	for (const auto &[version, tail] : {
		std::pair{ 3, 0 },
		std::pair{ 4, int(sizeof(qint32)) },
		std::pair{
			5,
			int(sizeof(qint32) * 4)
				+ int(server.serverSelection.size())
				+ int(server.discoveryOrigin.size())},
		std::pair{
			6,
			int(sizeof(qint32) * 5)
				+ int(server.serverSelection.size())
				+ int(server.discoveryOrigin.size())},
	}) {
		auto fixture = serialized.left(customBlockEnd + tail);
		QDataStream stream(&fixture, QIODevice::ReadWrite);
		stream.setVersion(QDataStream::Qt_5_1);
		stream << qint32(-version);

		auto restored = DcOptions(Environment::Production);
		CHECK(restored.constructFromSerialized(fixture));
		CHECK(restored.hasCustomServer());
		const auto got = restored.customServer();
		CHECK_EQ(got.dcId, server.dcId);
		CHECK_EQ(got.ip, server.ip);
		CHECK_EQ(got.port, server.port);
		CHECK(got.hostname.empty());
		CHECK(got.key != nullptr);
		if (got.key) {
			CHECK_EQ(qint64(got.key->fingerprint()), kProductionKeyFingerprint);
		}
	}
}

TEST_CASE(PinnedNon80EndpointRestoresAsDirectTcpOnly) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.ip = "100.124.236.66";
	server.port = 2443;
	CHECK(options.setCustomServer(server));

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));

	const auto direct = restored.lookup(server.dcId, DcType::Regular, false);
	const auto &directTcp = direct.data[DcOptions::Variants::IPv4]
		[DcOptions::Variants::Tcp];
	CHECK(directTcp.size() == 1);
	if (directTcp.size() == 1) {
		CHECK_EQ(directTcp.front().ip, server.ip);
		CHECK_EQ(directTcp.front().port, 2443);
	}
	CHECK(direct.data[DcOptions::Variants::IPv4]
		[DcOptions::Variants::Http].empty());

	const auto proxied = restored.lookup(server.dcId, DcType::Regular, true);
	const auto &proxiedTcp = proxied.data[DcOptions::Variants::IPv4]
		[DcOptions::Variants::Tcp];
	CHECK(proxiedTcp.size() == 1);
	if (proxiedTcp.size() == 1) {
		CHECK_EQ(proxiedTcp.front().ip, server.ip);
		CHECK_EQ(proxiedTcp.front().port, 2443);
	}
	CHECK(proxied.data[DcOptions::Variants::IPv4]
		[DcOptions::Variants::Http].empty());
}

TEST_CASE(PinnedEndpointUsesTcpThroughHttpProxy) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.ip = "100.124.236.66";
	server.port = 2443;
	CHECK(options.setCustomServer(server));

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));
	CHECK(restored.hasCustomServer());
	const auto pin = restored.customServer();
	CHECK_EQ(pin.ip, server.ip);
	CHECK_EQ(pin.port, server.port);
	CHECK(pin.key != nullptr);
	if (pin.key) {
		CHECK(pin.key->valid());
		CHECK_EQ(qint64(pin.key->fingerprint()), kProductionKeyFingerprint);
	}

	const auto checkProtocol = ProxyCheckProtocol(
		ProxyData::Type::Http,
		restored.hasCustomServer());
	CHECK(checkProtocol == DcOptions::Variants::Tcp);
	CHECK(ProxyCheckProtocol(
		ProxyData::Type::Http,
		false) == DcOptions::Variants::Http);

	const auto proxied = restored.lookup(server.dcId, DcType::Regular, true);
	const auto &proxiedTcp = proxied.data[DcOptions::Variants::IPv4][checkProtocol];
	CHECK(proxiedTcp.size() == 1);
	if (proxiedTcp.size() == 1) {
		CHECK_EQ(proxiedTcp.front().ip, server.ip);
		CHECK_EQ(proxiedTcp.front().port, 2443);
	}
	CHECK(proxied.data[DcOptions::Variants::IPv4]
		[DcOptions::Variants::Http].empty());
}

TEST_CASE(StartProxyCheckUsesVettedLiteralForAllTransportPaths) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.hostname = "telegram-server.tailaa4918.ts.net";
	server.ip.clear();
	server.port = 2443;
	server.serverSelection = server.hostname;
	server.discoveryPolicy = ServerDiscoveryPolicy::PublicHttps;
	server.discoveryOrigin =
		"https://telegram-server.tailaa4918.ts.net/"
		".well-known/telegramd/client";
	CHECK(options.setCustomServer(server));
	details::UnitProxyCheckOptions = &options;

	const auto fakeInstance = reinterpret_cast<Instance*>(quintptr(1));
	for (const auto proxyType : {
		ProxyData::Type::None,
		ProxyData::Type::Socks5,
		ProxyData::Type::Http,
	}) {
		UnitHostResolver resolver;
		resolver.add({
			.addresses = {
				QHostAddress(u"8.8.8.8"_q),
				QHostAddress(u"127.0.0.1"_q),
				QHostAddress(u"10.0.0.1"_q),
				QHostAddress(u"100.124.236.66"_q),
			},
		});
		ProxyData proxy;
		proxy.type = proxyType;
		proxy.host = u"127.0.0.1"_q;
		proxy.port = 1080;
		ProxyCheckObservation observation;
		bool done = false;
		bool failed = false;
		ProxyCheckConnection v4;
		ProxyCheckConnection v6;
		const details::UnitConnectionFactory factory = [&](
			not_null<Instance*>,
			DcOptions::Variants::Protocol protocol,
			QThread *thread,
			const bytes::vector &secret,
			const ProxyData &data) {
			CHECK(protocol == DcOptions::Variants::Tcp);
			return details::ConnectionPointer::New<ProxyCheckObserver>(
				thread,
				data,
				&observation);
		};
		details::UnitConnectionFactoryInstance = &factory;
		StartProxyCheck(
			not_null<Instance*>(fakeInstance),
			proxy,
			false,
			v4,
			v6,
			[&](details::AbstractConnection *, int) { done = true; },
			[&](details::AbstractConnection *) { failed = true; },
			resolver.resolver());

		CHECK(v4);
		CHECK(!v6);
		CHECK(done);
		CHECK(!failed);
		CHECK_EQ(
			observation.addressPassedToChild,
			u"100.124.236.66"_q);
		CHECK(observation.addressPassedToChild
			!= u"telegram-server.tailaa4918.ts.net"_q);
		CHECK_EQ(observation.port, 2443);
		CHECK(observation.proxyType == proxyType);
		v4.reset();
		details::UnitConnectionFactoryInstance = nullptr;
	}
	details::UnitProxyCheckOptions = nullptr;
}

TEST_CASE(StartProxyCheckRejectsFailedHostnameResolution) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.hostname = "telegram-server.tailaa4918.ts.net";
	server.ip.clear();
	server.port = 2443;
	server.serverSelection = server.hostname;
	server.discoveryPolicy = ServerDiscoveryPolicy::PublicHttps;
	server.discoveryOrigin =
		"https://telegram-server.tailaa4918.ts.net/"
		".well-known/telegramd/client";
	CHECK(options.setCustomServer(server));
	details::UnitProxyCheckOptions = &options;

	const auto fakeInstance = reinterpret_cast<Instance*>(quintptr(1));
	for (const auto &response : {
		UnitHostLookupResponse{
			.error = QHostInfo::HostNotFound,
		},
		UnitHostLookupResponse{
			.addresses = {
				QHostAddress(u"8.8.8.8"_q),
				QHostAddress(u"127.0.0.1"_q),
				QHostAddress(u"10.0.0.1"_q),
			},
		},
	}) {
		UnitHostResolver resolver;
		resolver.add(response);
		ProxyData proxy;
		proxy.type = ProxyData::Type::Socks5;
		proxy.host = u"127.0.0.1"_q;
		proxy.port = 1080;
		ProxyCheckObservation observation;
		int factoryCalls = 0;
		bool done = false;
		bool failed = false;
		ProxyCheckConnection v4;
		ProxyCheckConnection v6;
		const details::UnitConnectionFactory factory = [&](
			not_null<Instance*>,
			DcOptions::Variants::Protocol,
			QThread *thread,
			const bytes::vector &,
			const ProxyData &data) {
			++factoryCalls;
			return details::ConnectionPointer::New<ProxyCheckObserver>(
				thread,
				data,
				&observation);
		};
		details::UnitConnectionFactoryInstance = &factory;
		StartProxyCheck(
			not_null<Instance*>(fakeInstance),
			proxy,
			false,
			v4,
			v6,
			[&](details::AbstractConnection *, int) { done = true; },
			[&](details::AbstractConnection *) { failed = true; },
			resolver.resolver());

		CHECK(v4);
		CHECK(!v6);
		CHECK(!done);
		CHECK(failed);
		CHECK_EQ(factoryCalls, 0);
		CHECK(!observation.connected);
		v4.reset();
		details::UnitConnectionFactoryInstance = nullptr;
	}

	UnitHostResolver timeoutResolver;
	timeoutResolver.add({ .timeout = true });
	ProxyData proxy;
	proxy.type = ProxyData::Type::Http;
	proxy.host = u"127.0.0.1"_q;
	proxy.port = 8080;
	ProxyCheckObservation observation;
	int factoryCalls = 0;
	bool done = false;
	bool failed = false;
	ProxyCheckConnection v4;
	ProxyCheckConnection v6;
	const details::UnitConnectionFactory factory = [&](
		not_null<Instance*>,
		DcOptions::Variants::Protocol,
		QThread *thread,
		const bytes::vector &,
		const ProxyData &data) {
		++factoryCalls;
		return details::ConnectionPointer::New<ProxyCheckObserver>(
			thread,
			data,
			&observation);
	};
	details::UnitConnectionFactoryInstance = &factory;
	StartProxyCheck(
		not_null<Instance*>(fakeInstance),
		proxy,
		false,
		v4,
		v6,
		[&](details::AbstractConnection *, int) { done = true; },
		[&](details::AbstractConnection *) { failed = true; },
		timeoutResolver.resolver());
	CHECK(v4);
	CHECK(!done);
	CHECK(!failed);
	CHECK_EQ(factoryCalls, 0);
	v4->timedOut();
	CHECK(failed);
	CHECK_EQ(factoryCalls, 0);
	CHECK_EQ(timeoutResolver.aborts(), 1);
	v4.reset();
	details::UnitConnectionFactoryInstance = nullptr;
	details::UnitProxyCheckOptions = nullptr;
}

TEST_CASE(HostnameConnectionRetriesWithFreshResolution) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.hostname = "telegram-server.tailaa4918.ts.net";
	server.ip.clear();
	server.port = 2443;
	server.serverSelection = server.hostname;
	server.discoveryPolicy = ServerDiscoveryPolicy::PublicHttps;
	server.discoveryOrigin =
		"https://telegram-server.tailaa4918.ts.net/"
		".well-known/telegramd/client";
	CHECK(options.setCustomServer(server));
	details::UnitProxyCheckOptions = &options;

	UnitHostResolver resolver;
	resolver.add({
		.addresses = { QHostAddress(u"100.124.236.66"_q) },
	});
	resolver.add({
		.addresses = { QHostAddress(u"100.124.236.67"_q) },
	});
	const auto fakeInstance = reinterpret_cast<Instance*>(quintptr(1));
	ProxyData proxy;
	proxy.type = ProxyData::Type::Socks5;
	proxy.host = u"127.0.0.1"_q;
	proxy.port = 1080;
	QStringList dialled;
	for (auto i = 0; i != 2; ++i) {
		ProxyCheckObservation observation;
		bool done = false;
		bool failed = false;
		ProxyCheckConnection v4;
		ProxyCheckConnection v6;
		const details::UnitConnectionFactory factory = [&](
			not_null<Instance*>,
			DcOptions::Variants::Protocol,
			QThread *thread,
			const bytes::vector &,
			const ProxyData &data) {
			return details::ConnectionPointer::New<ProxyCheckObserver>(
				thread,
				data,
				&observation);
		};
		details::UnitConnectionFactoryInstance = &factory;
		StartProxyCheck(
			not_null<Instance*>(fakeInstance),
			proxy,
			false,
			v4,
			v6,
			[&](details::AbstractConnection *, int) { done = true; },
			[&](details::AbstractConnection *) { failed = true; },
			resolver.resolver());
		CHECK(done);
		CHECK(!failed);
		dialled.push_back(observation.addressPassedToChild);
		v4.reset();
		details::UnitConnectionFactoryInstance = nullptr;
	}
	CHECK_EQ(resolver.lookups(), 2);
	CHECK_EQ(dialled.value(0), u"100.124.236.66"_q);
	CHECK_EQ(dialled.value(1), u"100.124.236.67"_q);
	details::UnitProxyCheckOptions = nullptr;
}

TEST_CASE(DefaultHostnameResolverDoesNotReusePreviousAnswer) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.hostname = "resolver-test.tailaa4918.ts.net";
	server.ip.clear();
	server.port = 2443;
	server.serverSelection = server.hostname;
	server.discoveryPolicy = ServerDiscoveryPolicy::PublicHttps;
	server.discoveryOrigin =
		"https://resolver-test.tailaa4918.ts.net/"
		".well-known/telegramd/client";
	CHECK(options.setCustomServer(server));
	details::UnitProxyCheckOptions = &options;

	const auto answers = std::vector{
		QHostAddress(u"100.124.236.66"_q),
		QHostAddress(u"100.124.236.67"_q),
	};
	UnitHostResolver resolver;
	for (const auto &answer : answers) {
		resolver.add({ .addresses = { answer } });
	}
	SetDefaultHostnameResolver(resolver);

	const auto fakeInstance = reinterpret_cast<Instance*>(quintptr(1));
	ProxyData proxy;
	proxy.type = ProxyData::Type::Socks5;
	proxy.host = u"127.0.0.1"_q;
	proxy.port = 1080;
	QStringList dialled;
	for (const auto &expected : answers) {
		ProxyCheckObservation observation;
		bool done = false;
		bool failed = false;
		ProxyCheckConnection v4;
		ProxyCheckConnection v6;
		const details::UnitConnectionFactory factory = [&](
			not_null<Instance*>,
			DcOptions::Variants::Protocol,
			QThread *thread,
			const bytes::vector &,
			const ProxyData &data) {
			return details::ConnectionPointer::New<ProxyCheckObserver>(
				thread,
				data,
				&observation);
		};
		details::UnitConnectionFactoryInstance = &factory;
		QEventLoop loop;
		StartProxyCheck(
			not_null<Instance*>(fakeInstance),
			proxy,
			false,
			v4,
			v6,
			[&](details::AbstractConnection *, int) {
				done = true;
				loop.quit();
			},
			[&](details::AbstractConnection *) {
				failed = true;
				loop.quit();
			});
		if (!done && !failed) {
			QTimer::singleShot(2000, &loop, &QEventLoop::quit);
			loop.exec();
		}
		CHECK(done);
		CHECK(!failed);
		if (done) {
			dialled.push_back(observation.addressPassedToChild);
		}
		CHECK_EQ(observation.addressPassedToChild, expected.toString());
		v4.reset();
		details::UnitConnectionFactoryInstance = nullptr;
	}
	CHECK_EQ(resolver.lookups(), int(answers.size()));
	CHECK_EQ(dialled.value(0), answers[0].toString());
	CHECK_EQ(dialled.value(1), answers[1].toString());
	details::SetServerHostnameResolverTestLookup({});
	details::UnitProxyCheckOptions = nullptr;
}

#ifdef Q_OS_UNIX
TEST_CASE(DefaultHostnameResolverUsesSystemResolver) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.hostname = "system-resolver-fixture.test";
	server.ip.clear();
	server.port = 2443;
	server.serverSelection = server.hostname;
	server.discoveryPolicy = ServerDiscoveryPolicy::PublicHttps;
	server.discoveryOrigin =
		"https://system-resolver-fixture.test/"
		".well-known/telegramd/client";
	CHECK(options.setCustomServer(server));
	details::UnitProxyCheckOptions = &options;
	details::SetServerHostnameResolverTestLookup({});

	const auto answers = std::vector{
		QHostAddress(u"8.8.8.8"_q),
		QHostAddress(u"8.8.4.4"_q),
	};
	const auto proxyTypes = std::vector{
		ProxyData::Type::Socks5,
		ProxyData::Type::Http,
	};
	const uint32_t systemAnswers[] = {
		0x08080808,
		0x08080404,
		0x08080808,
		0x08080404,
	};
	UnitSystemResolverSetAnswers(systemAnswers, std::size(systemAnswers));

	const auto fakeInstance = reinterpret_cast<Instance*>(quintptr(1));
	ProxyData proxy;
	proxy.host = u"127.0.0.1"_q;
	proxy.port = 1080;
	QStringList dialled;
	for (const auto proxyType : proxyTypes) {
		proxy.type = proxyType;
		for (const auto &expected : answers) {
			ProxyCheckObservation observation;
			bool done = false;
			bool failed = false;
			ProxyCheckConnection v4;
			ProxyCheckConnection v6;
			const details::UnitConnectionFactory factory = [&](
				not_null<Instance*>,
				DcOptions::Variants::Protocol protocol,
				QThread *thread,
				const bytes::vector &,
				const ProxyData &data) {
				CHECK(protocol == DcOptions::Variants::Tcp);
				return details::ConnectionPointer::New<ProxyCheckObserver>(
					thread,
					data,
					&observation);
			};
			details::UnitConnectionFactoryInstance = &factory;
			QEventLoop loop;
			StartProxyCheck(
				not_null<Instance*>(fakeInstance),
				proxy,
				false,
				v4,
				v6,
				[&](details::AbstractConnection *, int) {
					done = true;
					loop.quit();
				},
				[&](details::AbstractConnection *) {
					failed = true;
					loop.quit();
				});
			if (!done && !failed) {
				QTimer::singleShot(2000, &loop, &QEventLoop::quit);
				loop.exec();
			}
			CHECK(done);
			CHECK(!failed);
			CHECK_EQ(observation.addressPassedToChild, expected.toString());
			CHECK(observation.addressPassedToChild
				!= u"system-resolver-fixture.test"_q);
			CHECK(observation.proxyType == proxyType);
			dialled.push_back(observation.addressPassedToChild);
			v4.reset();
			details::UnitConnectionFactoryInstance = nullptr;
		}
	}
	const auto expectedLookups = int(answers.size() * proxyTypes.size());
	CHECK_EQ(UnitSystemResolverLookups(), expectedLookups);
	CHECK_EQ(dialled.value(0), answers[0].toString());
	CHECK_EQ(dialled.value(1), answers[1].toString());
	CHECK_EQ(dialled.value(2), answers[0].toString());
	CHECK_EQ(dialled.value(3), answers[1].toString());
	UnitSystemResolverSetAnswers(nullptr, 0);
	details::UnitProxyCheckOptions = nullptr;
}

TEST_CASE(SystemResolverFixtureForwardsLocalhost) {
	const auto resolved = QHostInfo::fromName(u"localhost"_q);
	const auto addresses = resolved.addresses();
	CHECK(resolved.error() == QHostInfo::NoError);
	CHECK(std::any_of(
		addresses.cbegin(),
		addresses.cend(),
		[](const QHostAddress &address) { return address.isLoopback(); }));
}
#endif // Q_OS_UNIX

void RunDefaultResolverOwnerRemovalCase(
		bool proxyCheck,
		OwnerRemovalDnsResponse responseKind) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.hostname = "owner-removal-test.tailaa4918.ts.net";
	server.ip.clear();
	server.port = 2443;
	server.serverSelection = server.hostname;
	server.discoveryPolicy = ServerDiscoveryPolicy::PublicHttps;
	server.discoveryOrigin =
		"https://owner-removal-test.tailaa4918.ts.net/"
		".well-known/telegramd/client";
	CHECK(options.setCustomServer(server));
	details::UnitProxyCheckOptions = &options;
	UnitHostResolver resolver;
	switch (responseKind) {
	case OwnerRemovalDnsResponse::NoErrorNoData:
		resolver.add({});
		break;
	case OwnerRemovalDnsResponse::NxDomain:
		resolver.add({ .error = QHostInfo::HostNotFound });
		break;
	case OwnerRemovalDnsResponse::RejectedAddress:
		resolver.add({
			.addresses = { QHostAddress(u"8.8.8.8"_q) },
		});
		break;
	}
	SetDefaultHostnameResolver(resolver);

	const auto fakeInstance = reinterpret_cast<Instance*>(quintptr(1));
	ProxyData proxy;
	proxy.type = ProxyData::Type::Socks5;
	proxy.host = u"127.0.0.1"_q;
	proxy.port = 1080;
	QEventLoop loop;
	bool failed = false;
	if (proxyCheck) {
		ProxyCheckConnection v4;
		ProxyCheckConnection v6;
		StartProxyCheck(
			not_null<Instance*>(fakeInstance),
			proxy,
			false,
			v4,
			v6,
			[&](details::AbstractConnection *, int) {
				loop.quit();
			},
			[&](details::AbstractConnection *) {
				const auto owner = QPointer<details::AbstractConnection>(
					v4.get());
				CHECK(!owner.isNull());
				failed = true;
				ResetProxyCheckers(v4, v6);
				CHECK(owner.isNull());
				loop.quit();
			});
		QTimer::singleShot(2000, &loop, &QEventLoop::quit);
		loop.exec();
		CHECK(!v4);
		CHECK(!v6);
	} else {
		auto connection = details::CreateServerConnection(
			not_null<Instance*>(fakeInstance),
			DcOptions::Variants::Tcp,
			QThread::currentThread(),
			{},
			proxy,
			QString::fromStdString(server.hostname),
			false);
		QObject::connect(
			connection.get(),
			&details::AbstractConnection::error,
			[&](int) {
				const auto owner = QPointer<details::AbstractConnection>(
					connection.get());
				CHECK(!owner.isNull());
				failed = true;
				connection.reset();
				CHECK(owner.isNull());
				loop.quit();
			});
		connection->connectToServer(
			{},
			server.port,
			{},
			server.dcId,
			false);
		QTimer::singleShot(2000, &loop, &QEventLoop::quit);
		loop.exec();
		CHECK(!connection);
	}
	CHECK(failed);
	CHECK_EQ(resolver.lookups(), 1);

	details::SetServerHostnameResolverTestLookup({});
	details::UnitProxyCheckOptions = nullptr;
}

TEST_CASE(DefaultResolverSurvivesProxyCheckOwnerRemoval) {
	for (const auto responseKind : {
		OwnerRemovalDnsResponse::NoErrorNoData,
		OwnerRemovalDnsResponse::NxDomain,
		OwnerRemovalDnsResponse::RejectedAddress,
	}) {
		RunDefaultResolverOwnerRemovalCase(true, responseKind);
	}
}

TEST_CASE(DefaultResolverSurvivesSessionTestConnectionOwnerRemoval) {
	for (const auto responseKind : {
		OwnerRemovalDnsResponse::NoErrorNoData,
		OwnerRemovalDnsResponse::NxDomain,
		OwnerRemovalDnsResponse::RejectedAddress,
	}) {
		RunDefaultResolverOwnerRemovalCase(false, responseKind);
	}
}

TEST_CASE(UnboundBuiltinDcRetainsHttpTransportCandidate) {
	const auto options = DcOptions(Environment::Production);
	const auto variants = options.lookup(2, DcType::Regular, false);
	CHECK(!variants.data[DcOptions::Variants::IPv4]
		[DcOptions::Variants::Http].empty());
}

// An unpinned config must round-trip as unpinned rather than picking up
// a half-written pin, and must keep its production fallback.
TEST_CASE(UnpinnedConfigSurvivesSerialization) {
	auto options = DcOptions(Environment::Production);

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));

	CHECK(!restored.hasCustomServer());
	CHECK(!restored.refusesProductionFallback());
}

// An account that has not selected a server must retain an editable intro
// flow, but it must not retain Telegram's endpoint table or RSA keys while it
// waits there. The state also has to survive a config write and reload.
TEST_CASE(UnenrolledConfigHasNoProductionEndpointsOrKeys) {
	auto options = DcOptions(Environment::Production);
	options.constructUnenrolled();

	CHECK(options.unenrolled());
	CHECK(!options.blocked());
	CHECK(!options.hasCustomServer());
	CHECK(options.refusesProductionFallback());
	CHECK(options.configEnumDcIds().empty());
	CHECK(options.lookup(2, DcType::Regular, false).data[0][0].empty());
	CHECK(!options.getDcRSAKey(
		2,
		QVector<MTPlong>(1, MTP_long(kProductionKeyFingerprint))).valid());

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));
	CHECK(restored.unenrolled());
	CHECK(restored.configEnumDcIds().empty());
	CHECK(!restored.getDcRSAKey(
		2,
		QVector<MTPlong>(1, MTP_long(kProductionKeyFingerprint))).valid());

	CHECK(restored.setCustomServer(MakeCustomServer()));
	CHECK(!restored.unenrolled());
	CHECK(restored.hasCustomServer());
}

TEST_CASE(PermanentAuthKeyGateComesOnlyFromPersistedPin) {
	auto options = DcOptions(Environment::Production);
	CHECK(!options.usesPermanentAuthKey(2));

	const auto server = MakeCustomServer();
	CHECK(options.setCustomServer(server));
	CHECK(options.usesPermanentAuthKey(server.dcId));
	CHECK(!options.usesPermanentAuthKey(server.dcId + 1));
	CHECK(options.usesPermanentAuthKey(
		ShiftDcId(server.dcId, kConfigDcShift)));
	CHECK(options.usesPermanentAuthKey(
		ShiftDcId(server.dcId, kBaseDownloadDcShift)));
	CHECK(options.usesPermanentAuthKey(
		ShiftDcId(server.dcId, kBaseUploadDcShift)));

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));
	CHECK(restored.usesPermanentAuthKey(server.dcId));
	CHECK(!restored.usesPermanentAuthKey(server.dcId + 1));
	CHECK(restored.usesPermanentAuthKey(
		ShiftDcId(server.dcId, kConfigDcShift)));
	CHECK(restored.usesPermanentAuthKey(
		ShiftDcId(server.dcId, kBaseDownloadDcShift)));
	CHECK(restored.usesPermanentAuthKey(
		ShiftDcId(server.dcId, kBaseUploadDcShift)));

	auto blocked = DcOptions(Environment::Production);
	blocked.constructBlocked();
	CHECK(!blocked.usesPermanentAuthKey(server.dcId));
}

TEST_CASE(ServerSuppliedOptionsCannotEnablePermanentAuthKey) {
	auto options = DcOptions(Environment::Production);
	options.constructAddOne(
		2,
		DcOptions::Flag::f_static,
		"10.4.1.7",
		8443,
		{});

	CHECK(!options.hasCustomServer());
	CHECK(!options.usesPermanentAuthKey(2));
	CHECK(!options.usesPermanentAuthKey(
		ShiftDcId(2, kConfigDcShift)));
	CHECK(!options.usesPermanentAuthKey(
		ShiftDcId(2, kBaseDownloadDcShift)));
}

// A pin is all-or-nothing: a server with no key leaves an account that
// looks pinned but is not, so it has to be refused outright.
TEST_CASE(CustomServerWithoutAKeyIsRefused) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.key = nullptr;

	CHECK(!options.setCustomServer(server));
	CHECK(!options.hasCustomServer());
}

// A blocked account could not read its pinned settings back. It must be
// unable to reach any server at all rather than quietly fall back to
// Telegram's production DCs, so stored options must not reopen it.
TEST_CASE(BlockedConfigRefusesStoredOptions) {
	auto options = DcOptions(Environment::Production);
	CHECK(options.setCustomServer(MakeCustomServer()));
	const auto serialized = options.serialize();

	auto blocked = DcOptions(Environment::Production);
	blocked.constructBlocked();
	CHECK(blocked.blocked());

	CHECK(!blocked.constructFromSerialized(serialized));
	CHECK(blocked.blocked());
	CHECK(!blocked.hasCustomServer());
	CHECK(blocked.refusesProductionFallback());
}

TEST_CASE(SessionFeatureSupportUsesTheOwningConfig) {
	auto custom = DcOptions(Environment::Production);
	CHECK(custom.setCustomServer(MakeCustomServer()));
	auto blocked = DcOptions(Environment::Production);
	blocked.constructBlocked();
	auto stock = DcOptions(Environment::Production);
	stock.constructFromBuiltIn();

	CHECK(custom.hasCustomServer());
	CHECK(blocked.blocked());
	CHECK(!blocked.hasCustomServer());
	CHECK(!stock.blocked());
	CHECK(!stock.hasCustomServer());

	using Capability = bool (*)(const DcOptions &);
	const auto capabilities = std::array<Capability, 8>{
		Main::details::callsSupported,
		Main::details::botAppsSupported,
		Main::details::paidFeaturesSupported,
		Main::details::storiesSupported,
		Main::details::exportSupported,
		Main::details::passportSupported,
		Main::details::aiComposeSupported,
		Main::details::serverTranslationSupported,
	};
	for (const auto capability : capabilities) {
		CHECK(!capability(custom));
		CHECK(!capability(blocked));
		CHECK(capability(stock));
	}

	for (const auto capability : capabilities) {
		CHECK(!capability(custom));
		CHECK(capability(stock));
	}
	for (const auto capability : capabilities) {
		CHECK(capability(stock));
		CHECK(!capability(custom));
	}
}

// A pin is immutable for the life of the account. Peer and message ids
// are small server-scoped integers, so reading one server's cached ids
// against another sends a forward for "user 12345" to an unrelated
// person. A different pin must be refused and the original kept.
TEST_CASE(PinnedCustomServerRefusesADifferentPin) {
	auto options = DcOptions(Environment::Production);
	const auto original = MakeCustomServer();
	CHECK(options.setCustomServer(original));
	CHECK(options.markAuthorized(original.dcId));

	auto different = MakeCustomServer();
	different.ip = "10.4.1.8";
	CHECK(!options.setCustomServer(different));

	const auto got = options.customServer();
	CHECK_EQ(got.ip, original.ip);
	CHECK_EQ(got.port, original.port);
	CHECK(options.refusesProductionFallback());
}

// The key is what authenticates the server to the client, so the same
// endpoint with a different key is still a different server.
TEST_CASE(PinnedCustomServerRefusesADifferentKey) {
	auto options = DcOptions(Environment::Production);
	const auto original = MakeCustomServer();
	CHECK(options.setCustomServer(original));
	CHECK(options.markAuthorized(original.dcId));

	auto n = MakeKey()->getN();
	n.back() = bytes::type(
		gsl::to_integer<unsigned char>(n.back()) ^ 0x01);
	auto forged = std::make_shared<details::RSAPublicKey>(
		n,
		MakeKey()->getE());
	CHECK(forged->valid());

	auto different = MakeCustomServer();
	different.key = forged;
	CHECK(!options.setCustomServer(different));

	const auto got = options.customServer();
	CHECK(got.key != nullptr);
	if (got.key) {
		CHECK_EQ(qint64(got.key->fingerprint()), kProductionKeyFingerprint);
	}
}

// Before authorization, a pin is replaceable even when an auth key was
// already created for the first handshake.
TEST_CASE(PinReplaceableForNeverAuthorizedAccountAfterKeyExists) {
	auto options = DcOptions(Environment::Production);
	CHECK(options.setCustomServer(MakeCustomServer()));

	auto n = MakeKey()->getN();
	n.back() = bytes::type(
		gsl::to_integer<unsigned char>(n.back()) ^ 0x01);
	auto corrected = MakeCustomServer();
	corrected.key = std::make_shared<details::RSAPublicKey>(
		n,
		MakeKey()->getE());
	CHECK(corrected.key->valid());

	CHECK(options.setCustomServer(corrected));

	const auto got = options.customServer();
	CHECK(got.key != nullptr);
	if (got.key) {
		CHECK_EQ(
			qint64(got.key->fingerprint()),
			qint64(corrected.key->fingerprint()));
	}
}

// The first config response can report a different DC after the
// handshake. Before authorization, correcting that pin is still allowed.
TEST_CASE(PinReplaceableForNeverAuthorizedAccountAfterDcIdMismatch) {
	auto options = DcOptions(Environment::Production);
	const auto original = MakeCustomServer();
	CHECK(options.setCustomServer(original));

	auto corrected = MakeCustomServer();
	corrected.dcId = 3;
	corrected.ip = "10.4.1.8";

	CHECK(options.setCustomServer(corrected));

	const auto got = options.customServer();
	CHECK_EQ(got.dcId, corrected.dcId);
}

TEST_CASE(AuthorizedAccountStillRefusesADifferentPin) {
	auto options = DcOptions(Environment::Production);
	const auto original = MakeCustomServer();
	CHECK(options.setCustomServer(original));
	CHECK(options.markAuthorized(original.dcId));

	auto different = MakeCustomServer();
	different.ip = "10.4.1.8";
	different.dcId = 3;
	CHECK(!options.setCustomServer(different));
}

// Authorization is independent of the mutable auth-key store. It remains
// present after a config round trip, which models relaunch and key churn.
TEST_CASE(AuthorizationMarkerSurvivesKeyRemoval) {
	auto options = DcOptions(Environment::Production);
	const auto original = MakeCustomServer();
	CHECK(options.setCustomServer(original));
	CHECK(options.markAuthorized(original.dcId));

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));
	CHECK(restored.isAuthorized(original.dcId));

	auto different = MakeCustomServer();
	different.ip = "10.4.1.8";
	different.dcId = 3;
	CHECK(!restored.setCustomServer(different));
}

TEST_CASE(FullAccountResetClearsAuthorizationMarker) {
	auto options = DcOptions(Environment::Production);
	const auto original = MakeCustomServer();
	CHECK(options.setCustomServer(original));
	CHECK(options.markAuthorized(original.dcId));
	CHECK(options.clearAuthorized());
	CHECK(!options.isAuthorized(original.dcId));

	auto replacement = MakeCustomServer();
	replacement.ip = "10.4.1.8";
	CHECK(options.setCustomServer(replacement));
}

// Startup and config rewrites re-apply the stored pin through the same
// setter, so the identical pin must stay allowed.
TEST_CASE(ReapplyingTheIdenticalPinSucceeds) {
	auto options = DcOptions(Environment::Production);
	CHECK(options.setCustomServer(MakeCustomServer()));

	CHECK(options.setCustomServer(MakeCustomServer()));
	CHECK(options.hasCustomServer());
	CHECK(options.refusesProductionFallback());

	const auto serialized = options.serialize();
	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(serialized));
	CHECK(restored.isCustomServerPinned(MakeCustomServer().dcId));
}

// The first connection is the first operation that can identify the user
// to the newly pinned server. The exact endpoint and key therefore have to
// be serialized before that connection is allowed to start.
TEST_CASE(EnrollmentPinIsPersistedBeforeTheFirstConnection) {
	auto options = DcOptions(Environment::Production);
	const auto server = MakeCustomServer();
	auto serialized = QByteArray();
	auto connected = false;

	CHECK(CommitServerEnrollment(
		[&] { return options.setCustomServer(server); },
		[&] {
			serialized = options.serialize();
			return true;
		},
		[&] {
			connected = true;
			CHECK(!serialized.isEmpty());
		}));

	CHECK(connected);
	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(serialized));
	const auto got = restored.customServer();
	CHECK_EQ(got.dcId, server.dcId);
	CHECK_EQ(got.ip, server.ip);
	CHECK_EQ(got.port, server.port);
	CHECK(got.key != nullptr);
	if (got.key) {
		CHECK_EQ(qint64(got.key->fingerprint()),
			qint64(server.key->fingerprint()));
	}
}

// The check and the apply must be one atomic step under the write lock.
// With the comparison in a separate read-lock scope, two concurrent
// callers can each observe an unpinned account, both proceed, and the
// later write replaces the first pin. Two distinct servers hammered at
// one DcOptions must therefore never both get accepted.
TEST_CASE(ConcurrentSetCustomServerAcceptsOnlyOneDistinctPin) {
	auto other = MakeCustomServer();
	other.ip = "10.4.1.9";

	constexpr auto kPasses = 100;
	constexpr auto kThreads = 8;

	// A single gated pass hits the losing interleaving of the broken
	// read-check-then-write pattern only a few percent of the time, so
	// one pass pins nothing. The whole scenario repeats from a fresh
	// DcOptions every pass and the invariant is asserted on each: a
	// reintroduction has to survive a hundred fresh chances.
	for (auto pass = 0; pass != kPasses; ++pass) {
		auto options = DcOptions(Environment::Production);
		CHECK(options.markAuthorized(2));

		std::atomic<int> acceptedOriginal = 0;
		std::atomic<int> acceptedOther = 0;

		// Every thread waits at the gate until all of them are ready,
		// so the calls really overlap instead of serialising by
		// accident.
		std::atomic<int> ready = 0;
		std::atomic<bool> go = false;

		auto threads = std::vector<std::thread>();
		threads.reserve(kThreads);
		for (auto i = 0; i != kThreads; ++i) {
			const auto attemptOriginal = (i % 2) == 0;
			// attemptOriginal is a loop-body local: it must be captured
			// by value, the thread runs long after the iteration is
			// over.
			threads.emplace_back([&, attemptOriginal] {
				++ready;
				while (!go.load(std::memory_order_acquire)) {
					std::this_thread::yield();
				}
				const auto ok = options.setCustomServer(
					attemptOriginal ? MakeCustomServer() : other);
				(attemptOriginal ? acceptedOriginal : acceptedOther)
					+= (ok ? 1 : 0);
			});
		}
		while (ready.load() != kThreads) {
			std::this_thread::yield();
		}
		go.store(true, std::memory_order_release);
		for (auto &thread : threads) {
			thread.join();
		}

		CHECK((acceptedOriginal == 0) || (acceptedOther == 0));
		CHECK((acceptedOriginal + acceptedOther) > 0);
		const auto got = options.customServer();
		if (acceptedOriginal > 0) {
			CHECK_EQ(got.ip, MakeCustomServer().ip);
		} else {
			CHECK_EQ(got.ip, other.ip);
		}
	}
}

// A refused overwrite returns before any state is touched, so it must
// not lift or weaken the production-fallback block.
TEST_CASE(RefusedOverwriteLeavesFallbackBlockInForce) {
	auto options = DcOptions(Environment::Production);
	const auto original = MakeCustomServer();
	CHECK(options.setCustomServer(original));
	CHECK(options.markAuthorized(original.dcId));
	CHECK(options.refusesProductionFallback());

	auto different = MakeCustomServer();
	different.ip = "10.4.1.8";
	CHECK(!options.setCustomServer(different));
	CHECK(options.refusesProductionFallback());
	CHECK(options.isCustomServerPinned(different.dcId));

	// The no-key refusal keeps the same property.
	auto keyless = MakeCustomServer();
	keyless.key = nullptr;
	CHECK(!options.setCustomServer(keyless));
	CHECK(options.refusesProductionFallback());
}
