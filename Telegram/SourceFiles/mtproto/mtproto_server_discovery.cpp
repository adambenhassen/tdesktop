/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/mtproto_server_discovery.h"

#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonParseError>
#include <QtCore/QSet>
#include <QtCore/QUrl>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QTcpSocket>

#if defined Q_OS_WIN
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstring>
#include <initializer_list>
#include <optional>
#include <utility>

namespace MTP {
namespace {

constexpr auto kMaxSelectionBytes = 1024;
constexpr auto kMaxLabelBytes = 63;
constexpr auto kMaxNameBytes = 253;
constexpr auto kMaxResponseBytes = 16 * 1024;
constexpr auto kMaxSpkiBytes = 4096;
constexpr auto kRequiredModulusBits = 2048;
constexpr auto kMaxJsonDepth = 8;
constexpr auto kMaxJsonValues = 64;
constexpr auto kLocalRequestMagic = "telegramd-key-v1";
constexpr auto kLocalResponseMagic = "telegramd-key-r1";
constexpr auto kMaxServerDiscoveryAttempts = 4;

std::atomic<int> ServerDiscoveryAttempts = 0;

[[nodiscard]] bool IsAsciiDigit(QChar ch) {
	const auto code = ch.unicode();
	return code >= '0' && code <= '9';
}

[[nodiscard]] bool IsInSubnet(
		const QHostAddress &address,
		const char *subnet,
		int bits) {
	return address.isInSubnet(QHostAddress(QString::fromLatin1(subnet)), bits);
}

struct AddressSubnet {
	const char *address;
	int bits;
};

// Keep these blocks synchronized with the IANA Special-Purpose Address
// Registries. Public discovery accepts only ordinary globally routable
// unicast addresses; protocol, private, reserved, and documentation blocks
// stay rejected even when a DNS answer or delegated literal names them.
constexpr auto kNonGlobalIpv4 = {
	AddressSubnet{ "0.0.0.0", 8 },
	AddressSubnet{ "10.0.0.0", 8 },
	AddressSubnet{ "100.64.0.0", 10 },
	AddressSubnet{ "127.0.0.0", 8 },
	AddressSubnet{ "169.254.0.0", 16 },
	AddressSubnet{ "172.16.0.0", 12 },
	AddressSubnet{ "192.0.0.0", 24 },
	AddressSubnet{ "192.0.2.0", 24 },
	AddressSubnet{ "192.31.196.0", 24 },
	AddressSubnet{ "192.52.193.0", 24 },
	AddressSubnet{ "192.88.99.0", 24 },
	AddressSubnet{ "192.168.0.0", 16 },
	AddressSubnet{ "192.175.48.0", 24 },
	AddressSubnet{ "198.18.0.0", 15 },
	AddressSubnet{ "198.51.100.0", 24 },
	AddressSubnet{ "203.0.113.0", 24 },
	AddressSubnet{ "224.0.0.0", 4 },
	AddressSubnet{ "240.0.0.0", 4 },
};

constexpr auto kNonGlobalIpv6 = {
	AddressSubnet{ "::", 128 },
	AddressSubnet{ "::1", 128 },
	AddressSubnet{ "::ffff:0:0", 96 },
	AddressSubnet{ "64:ff9b::", 96 },
	AddressSubnet{ "64:ff9b:1::", 48 },
	AddressSubnet{ "100::", 64 },
	AddressSubnet{ "100:0:0:1::", 64 },
	AddressSubnet{ "2001::", 23 },
	AddressSubnet{ "2001:4:112::", 48 },
	AddressSubnet{ "2001:db8::", 32 },
	AddressSubnet{ "2002::", 16 },
	AddressSubnet{ "2620:4f:8000::", 48 },
	AddressSubnet{ "3fff::", 20 },
	AddressSubnet{ "5f00::", 16 },
	AddressSubnet{ "fc00::", 7 },
	AddressSubnet{ "fe80::", 10 },
};

[[nodiscard]] bool IsInAnySubnet(
		const QHostAddress &address,
		std::initializer_list<AddressSubnet> subnets) {
	for (const auto &subnet : subnets) {
		if (IsInSubnet(address, subnet.address, subnet.bits)) {
			return true;
		}
	}
	return false;
}

[[nodiscard]] bool IsGloballyRoutableUnicast(const QHostAddress &address) {
	if (address.protocol() == QAbstractSocket::IPv6Protocol
		&& IsInSubnet(address, "::ffff:0:0", 96)) {
		return IsGloballyRoutableUnicast(QHostAddress(address.toIPv4Address()));
	}
	if (address.protocol() == QAbstractSocket::IPv4Protocol) {
		return !IsInAnySubnet(address, kNonGlobalIpv4);
	}
	if (address.protocol() != QAbstractSocket::IPv6Protocol) {
		return false;
	}
	// Only 2000::/3 is allocated to IPv6 global unicast. This outer
	// allow-list rejects future, reserved, and special-purpose space by
	// default; the table handles special assignments within that range.
	return IsInSubnet(address, "2000::", 3)
		&& !IsInAnySubnet(address, kNonGlobalIpv6);
}

[[nodiscard]] bool IsRejectedLiteral(const QHostAddress &address) {
	if (address.protocol() == QAbstractSocket::IPv6Protocol
		&& IsInSubnet(address, "::ffff:0:0", 96)) {
		return IsRejectedLiteral(QHostAddress(address.toIPv4Address()));
	}
	if (address.protocol() == QAbstractSocket::IPv4Protocol) {
		return IsInSubnet(address, "0.0.0.0", 32)
			|| IsInSubnet(address, "224.0.0.0", 4)
			|| IsInSubnet(address, "255.255.255.255", 32);
	}
	return IsInSubnet(address, "::", 128)
		|| IsInSubnet(address, "ff00::", 8);
}

[[nodiscard]] bool IsLocalName(const QString &host) {
	return !host.contains(QChar::fromLatin1('.'))
		|| host == u"localhost"_q
		|| host.endsWith(u".localhost"_q)
		|| host.endsWith(u".local"_q)
		|| host.endsWith(u".home.arpa"_q);
}

[[nodiscard]] bool IsValidAsciiName(const QString &host) {
	if (host.isEmpty() || host.toUtf8().size() > kMaxNameBytes) {
		return false;
	}
	auto total = 0;
	for (const auto &label : host.split(QChar::fromLatin1('.'))) {
		const auto bytes = label.toUtf8();
		if (bytes.isEmpty() || bytes.size() > kMaxLabelBytes) {
			return false;
		}
		if (label.front() == QChar::fromLatin1('-')
			|| label.back() == QChar::fromLatin1('-')) {
			return false;
		}
		for (const auto ch : label) {
			const auto code = ch.unicode();
			if (!((code >= 'a' && code <= 'z')
				|| (code >= '0' && code <= '9')
				|| code == '-')) {
				return false;
			}
		}
		total += bytes.size() + (total ? 1 : 0);
	}
	return total <= kMaxNameBytes;
}

[[nodiscard]] ServerSelectionCheck SelectionFailure(
		ServerSelectionStatus status) {
	return { .status = status };
}

[[nodiscard]] std::optional<QString> CanonicalHost(const QString &input) {
	if (input.isEmpty() || input.contains('%')) {
		return std::nullopt;
	}
	auto host = input;
	if (host.endsWith(QChar::fromLatin1('.'))) {
		host.chop(1);
	}
	if (host.isEmpty()) {
		return std::nullopt;
	}
	const auto ace = QUrl::toAce(host);
	if (ace.isEmpty()) {
		return std::nullopt;
	}
	const auto result = QString::fromLatin1(ace).toLower();
	return IsValidAsciiName(result)
		? std::optional<QString>(result)
		: std::nullopt;
}

[[nodiscard]] bool HostExceedsNameLimit(const QString &input) {
	auto host = input;
	if (host.endsWith(QChar::fromLatin1('.'))) {
		host.chop(1);
	}
	const auto ace = QUrl::toAce(host);
	if (ace.isEmpty()) {
		return false;
	}
	const auto canonical = QString::fromLatin1(ace);
	if (canonical.toUtf8().size() > kMaxNameBytes) {
		return true;
	}
	for (const auto &label : canonical.split(QChar::fromLatin1('.'))) {
		if (label.toUtf8().size() > kMaxLabelBytes) {
			return true;
		}
	}
	return false;
}

[[nodiscard]] QString EndpointFor(
		const QString &host,
		bool ipv6,
		int port) {
	return (ipv6 ? (u"["_q + host + u"]"_q) : host)
		+ u":"_q
		+ QString::number(port);
}

[[nodiscard]] std::optional<details::RSAPublicKey> ParseSpki(
		const QByteArray &der) {
	if (der.isEmpty() || der.size() > kMaxSpkiBytes) {
		return std::nullopt;
	}
	const auto base64 = der.toBase64();
	auto pem = QByteArray("-----BEGIN PUBLIC KEY-----\n");
	for (auto i = 0; i < base64.size(); i += 64) {
		pem += base64.mid(i, 64);
		pem += '\n';
	}
	pem += "-----END PUBLIC KEY-----\n";
	auto key = details::RSAPublicKey(bytes::make_span(pem));
	if (!key.valid() || key.modulusBits() != kRequiredModulusBits) {
		return std::nullopt;
	}
	const auto normalized = key.getSubjectPublicKeyInfo();
	const auto modulus = key.getN();
	const auto exponent = key.getE();
	const auto isOdd = [](const auto &value) {
		return !value.empty()
			&& (gsl::to_integer<uchar>(value.back()) & 1);
	};
	if (!isOdd(modulus)
		|| !isOdd(exponent)
		|| (exponent.size() == 1
			&& gsl::to_integer<uchar>(exponent.front()) < 3)
		|| normalized.size() != der.size()
		|| QByteArray(
			reinterpret_cast<const char *>(normalized.data()),
			normalized.size()) != der) {
		return std::nullopt;
	}
	return key;
}

class JsonKeyValidator final {
public:
	explicit JsonKeyValidator(const QByteArray &data) : _data(data) {
	}

	[[nodiscard]] bool valid() {
		if (!parseValue(0)) {
			return false;
		}
		skipWhitespace();
		return _position == _data.size();
	}

private:
	[[nodiscard]] bool parseValue(int depth) {
		if (depth > kMaxJsonDepth) {
			return false;
		}
		skipWhitespace();
		if (_position == _data.size()) {
			return false;
		}
		switch (_data[_position]) {
		case '{':
			return parseObject(depth + 1);
		case '[':
			return parseArray(depth + 1);
		case '"':
			return parseString(nullptr);
		case 't':
			return parseLiteral("true");
		case 'f':
			return parseLiteral("false");
		case 'n':
			return parseLiteral("null");
		default:
			return parseNumber();
		}
	}

	[[nodiscard]] bool parseObject(int depth) {
		++_position;
		skipWhitespace();
		if (consume('}')) {
			return true;
		}
		QSet<QString> keys;
		for (auto members = 0; members != kMaxJsonValues; ++members) {
			QString key;
			if (!parseString(&key) || keys.contains(key)) {
				return false;
			}
			keys.insert(std::move(key));
			skipWhitespace();
			if (!consume(':') || !parseValue(depth)) {
				return false;
			}
			skipWhitespace();
			if (consume('}')) {
				return true;
			}
			if (!consume(',')) {
				return false;
			}
			skipWhitespace();
		}
		return false;
	}

	[[nodiscard]] bool parseArray(int depth) {
		++_position;
		skipWhitespace();
		if (consume(']')) {
			return true;
		}
		for (auto values = 0; values != kMaxJsonValues; ++values) {
			if (!parseValue(depth)) {
				return false;
			}
			skipWhitespace();
			if (consume(']')) {
				return true;
			}
			if (!consume(',')) {
				return false;
			}
			skipWhitespace();
		}
		return false;
	}

	[[nodiscard]] bool parseString(QString *result) {
		if (!consume('"')) {
			return false;
		}
		auto value = QString();
		while (_position < _data.size()) {
			const auto start = _position;
			while (_position < _data.size()) {
				const auto ch = uchar(_data[_position]);
				if (ch == '"' || ch == '\\' || ch < 0x20) {
					break;
				}
				++_position;
			}
			if (_position != start) {
				value += QString::fromUtf8(
					_data.constData() + start,
					_position - start);
				continue;
			}
			if (_position == _data.size()) {
				return false;
			}
			const auto ch = _data[_position++];
			if (ch == '"') {
				if (result) {
					*result = std::move(value);
				}
				return true;
			} else if (ch != '\\' || _position == _data.size()) {
				return false;
			}
			switch (_data[_position++]) {
			case '"': value += QChar('"'); break;
			case '\\': value += QChar('\\'); break;
			case '/': value += QChar('/'); break;
			case 'b': value += QChar('\b'); break;
			case 'f': value += QChar('\f'); break;
			case 'n': value += QChar('\n'); break;
			case 'r': value += QChar('\r'); break;
			case 't': value += QChar('\t'); break;
			case 'u': {
				if (_position + 4 > _data.size()) {
					return false;
				}
				uint code = 0;
				for (auto digits = 0; digits != 4; ++digits) {
					const auto digit = HexDigit(_data[_position++]);
					if (digit < 0) {
						return false;
					}
					code = (code << 4) | uint(digit);
				}
				value += QChar(ushort(code));
			} break;
			default:
				return false;
			}
		}
		return false;
	}

	[[nodiscard]] bool parseLiteral(const char *literal) {
		const auto length = int(strlen(literal));
		if (_position + length > _data.size()
			|| memcmp(_data.constData() + _position, literal, length) != 0) {
			return false;
		}
		_position += length;
		return true;
	}

	[[nodiscard]] bool parseNumber() {
		const auto start = _position;
		(void)consume('-');
		if (_position == _data.size()) {
			return false;
		}
		if (_data[_position] == '0') {
			++_position;
		} else if (_data[_position] >= '1' && _data[_position] <= '9') {
			while (_position < _data.size()
				&& _data[_position] >= '0'
				&& _data[_position] <= '9') {
				++_position;
			}
		} else {
			return false;
		}
		if (_position < _data.size() && _data[_position] == '.') {
			++_position;
			const auto fraction = _position;
			while (_position < _data.size()
				&& _data[_position] >= '0'
				&& _data[_position] <= '9') {
				++_position;
			}
			if (_position == fraction) {
				return false;
			}
		}
		if (_position < _data.size()
			&& (_data[_position] == 'e' || _data[_position] == 'E')) {
			++_position;
			(void)consume('+');
			(void)consume('-');
			const auto exponent = _position;
			while (_position < _data.size()
				&& _data[_position] >= '0'
				&& _data[_position] <= '9') {
				++_position;
			}
			if (_position == exponent) {
				return false;
			}
		}
		return _position != start;
	}

	[[nodiscard]] bool consume(char expected) {
		if (_position == _data.size() || _data[_position] != expected) {
			return false;
		}
		++_position;
		return true;
	}

	void skipWhitespace() {
		while (_position < _data.size()) {
			switch (_data[_position]) {
			case ' ': case '\t': case '\n': case '\r':
				++_position;
				break;
			default:
				return;
			}
		}
	}

	[[nodiscard]] static int HexDigit(char value) {
		if (value >= '0' && value <= '9') return value - '0';
		if (value >= 'a' && value <= 'f') return value - 'a' + 10;
		if (value >= 'A' && value <= 'F') return value - 'A' + 10;
		return -1;
	}

	const QByteArray &_data;
	int _position = 0;
};

[[nodiscard]] bool HasRequiredKeys(
		const QJsonObject &object,
		std::initializer_list<const char *> keys) {
	for (const auto key : keys) {
		if (!object.contains(QString::fromLatin1(key))) {
			return false;
		}
	}
	return true;
}

[[nodiscard]] ServerDiscoveryResult Invalid(
		ServerDiscoveryResponseStatus status) {
	return { .status = status };
}

} // namespace

std::optional<ServerDiscoveryAttempt> ServerDiscoveryAttempt::Acquire() {
	auto current = ServerDiscoveryAttempts.load(std::memory_order_relaxed);
	while (current < kMaxServerDiscoveryAttempts
		&& !ServerDiscoveryAttempts.compare_exchange_weak(
			current,
			current + 1,
			std::memory_order_relaxed,
			std::memory_order_relaxed)) {
	}
	if (current >= kMaxServerDiscoveryAttempts) {
		return std::nullopt;
	}
	return ServerDiscoveryAttempt(true);
}

ServerDiscoveryAttempt::ServerDiscoveryAttempt(
		ServerDiscoveryAttempt &&other) noexcept
: _held(std::exchange(other._held, false)) {
}

ServerDiscoveryAttempt &ServerDiscoveryAttempt::operator=(
		ServerDiscoveryAttempt &&other) noexcept {
	if (this != &other) {
		if (std::exchange(_held, false)) {
			ServerDiscoveryAttempts.fetch_sub(
				1,
				std::memory_order_relaxed);
		}
		_held = std::exchange(other._held, false);
	}
	return *this;
}

ServerDiscoveryAttempt::~ServerDiscoveryAttempt() {
	if (_held) {
		ServerDiscoveryAttempts.fetch_sub(
			1,
			std::memory_order_relaxed);
	}
}

ServerSelectionCheck CheckServerSelection(const QString &value) {
	if (value.toUtf8().size() > kMaxSelectionBytes) {
		return SelectionFailure(ServerSelectionStatus::HostTooLong);
	}
	const auto trimmed = value.trimmed();
	if (trimmed.isEmpty()) {
		return SelectionFailure(ServerSelectionStatus::Empty);
	}
	if (trimmed.contains(QChar::fromLatin1('@'))
		|| trimmed.contains(QChar::fromLatin1('/'))
		|| trimmed.contains(QChar::fromLatin1('?'))
		|| trimmed.contains(QChar::fromLatin1('#'))
		|| trimmed.contains(QChar::fromLatin1('%'))) {
		return SelectionFailure(ServerSelectionStatus::BadHost);
	}

	const auto bracketed = trimmed.startsWith(QChar::fromLatin1('['));
	auto hostText = QString();
	auto portText = QString();
	auto explicitPort = false;
	if (bracketed) {
		const auto close = trimmed.indexOf(QChar::fromLatin1(']'));
		if (close <= 1) {
			return SelectionFailure(ServerSelectionStatus::BadHost);
		}
		if (trimmed.indexOf(QChar::fromLatin1(']'), close + 1) >= 0) {
			return SelectionFailure(ServerSelectionStatus::BadHost);
		}
		hostText = trimmed.mid(1, close - 1);
		const auto rest = trimmed.mid(close + 1);
		if (rest.isEmpty()) {
			return SelectionFailure(ServerSelectionStatus::NoPort);
		} else if (!rest.startsWith(QChar::fromLatin1(':'))) {
			return SelectionFailure(ServerSelectionStatus::BadPort);
		}
		portText = rest.mid(1);
		explicitPort = true;
	} else {
		const auto firstColon = trimmed.indexOf(QChar::fromLatin1(':'));
		const auto lastColon = trimmed.lastIndexOf(QChar::fromLatin1(':'));
		if (firstColon >= 0 && firstColon != lastColon) {
			return SelectionFailure(ServerSelectionStatus::UnbracketedIPv6);
		} else if (firstColon >= 0) {
			hostText = trimmed.left(firstColon);
			portText = trimmed.mid(firstColon + 1);
			explicitPort = true;
		} else {
			hostText = trimmed;
		}
	}

	if (hostText.isEmpty()) {
		return SelectionFailure(ServerSelectionStatus::EmptyHost);
	}
	if (explicitPort) {
		if (portText.isEmpty()
			|| std::find_if(portText.begin(), portText.end(), [](QChar ch) {
				return !IsAsciiDigit(ch);
			}) != portText.end()) {
			return SelectionFailure(ServerSelectionStatus::BadPort);
		}
		bool ok = false;
		const auto port = portText.toInt(&ok);
		if (!ok || port < 1 || port > 65535) {
			return SelectionFailure(ServerSelectionStatus::BadPort);
		}
	}

	auto literal = QHostAddress();
	const auto isLiteral = literal.setAddress(hostText);
	if (bracketed && !isLiteral) {
		return SelectionFailure(ServerSelectionStatus::BadHost);
	}

	const auto ipv6 = isLiteral
		&& literal.protocol() == QAbstractSocket::IPv6Protocol;
	if (bracketed && isLiteral && !ipv6) {
		return SelectionFailure(ServerSelectionStatus::BadHost);
	}
	if (isLiteral) {
		if (IsRejectedLiteral(literal)) {
			return SelectionFailure(ServerSelectionStatus::InvalidSpecialAddress);
		}
		// QHostAddress accepts several textual spellings. Persist and route
		// only the canonical spelling so an equivalent input cannot change
		// the endpoint identity later.
		if (hostText != literal.toString().toLower()) {
			return SelectionFailure(ServerSelectionStatus::BadHost);
		}
	}
	if (!isLiteral && HostExceedsNameLimit(hostText)) {
		return SelectionFailure(ServerSelectionStatus::HostTooLong);
	}

	auto host = QString();
	if (isLiteral) {
		host = literal.toString().toLower();
	} else {
		const auto canonical = CanonicalHost(hostText);
		if (!canonical) {
			return SelectionFailure(ServerSelectionStatus::BadHost);
		}
		host = *canonical;
	}

	const auto localName = !isLiteral && IsLocalName(host);
	// Every IP literal is local-direct: a literal has no WebPKI hostname to
	// authenticate, so it must use the explicit-port preflight even when it
	// is globally routable. Unspecified, multicast, and broadcast literals
	// were rejected above; other special-use literals remain eligible when
	// selected directly.
	const auto localLiteral = isLiteral;
	const auto local = localName || localLiteral;
	if (local && !explicitPort) {
		return SelectionFailure(ServerSelectionStatus::NoPort);
	}
	const auto port = explicitPort ? portText.toInt() : 443;
	const auto policy = local
		? ServerDiscoveryPolicy::LocalDirect
		: ServerDiscoveryPolicy::PublicHttps;
	const auto normalizedSelection = explicitPort
		? EndpointFor(host, ipv6, port)
		: host;
	return {
		.status = ServerSelectionStatus::Valid,
		.host = host,
		.normalizedSelection = normalizedSelection,
		.requestedPort = explicitPort ? port : 0,
		.operationalPort = port,
		.ipv6 = ipv6,
		.explicitPort = explicitPort,
		.policy = policy,
	};
}

bool IsPublicAddress(const QHostAddress &address) {
	return IsGloballyRoutableUnicast(address);
}

bool IsPublicDiscoveryEndpoint(
		const ServerSelectionCheck &selection) {
	if (!selection.valid() || !selection.explicitPort) {
		return false;
	}
	auto address = QHostAddress();
	if (address.setAddress(selection.host)) {
		return IsPublicAddress(address);
	}
	return selection.policy == ServerDiscoveryPolicy::PublicHttps;
}

QString PublicDiscoveryUrl(const ServerSelectionCheck &selection) {
	if (!selection.valid()
		|| selection.policy != ServerDiscoveryPolicy::PublicHttps) {
		return {};
	}
	return u"https://"_q
		+ selection.host
		+ u"/.well-known/telegramd/client"_q;
}

void ConfigurePublicDiscoveryRequest(QNetworkRequest &request) {
	request.setRawHeader("User-Agent", QByteArrayLiteral("-"));
	request.setAttribute(
		QNetworkRequest::RedirectPolicyAttribute,
		QNetworkRequest::ManualRedirectPolicy);
	request.setAttribute(
		QNetworkRequest::CacheLoadControlAttribute,
		QNetworkRequest::AlwaysNetwork);
	request.setAttribute(
		QNetworkRequest::CacheSaveControlAttribute,
		false);
	request.setAttribute(
		QNetworkRequest::CookieLoadControlAttribute,
		QNetworkRequest::Manual);
	request.setAttribute(
		QNetworkRequest::CookieSaveControlAttribute,
		QNetworkRequest::Manual);
}

ServerDiscoveryResult ParsePublicDiscoveryResponse(
		const ServerSelectionCheck &selection,
		const QByteArray &body) {
	if (!selection.valid()
		|| selection.policy != ServerDiscoveryPolicy::PublicHttps) {
		return Invalid(ServerDiscoveryResponseStatus::UnsafeEndpoint);
	}
	if (body.isEmpty() || body.size() > kMaxResponseBytes) {
		return Invalid(ServerDiscoveryResponseStatus::InvalidJson);
	}
	if (!JsonKeyValidator(body).valid()) {
		return Invalid(ServerDiscoveryResponseStatus::InvalidJson);
	}
	QJsonParseError error;
	const auto document = QJsonDocument::fromJson(body, &error);
	if (error.error != QJsonParseError::NoError || !document.isObject()) {
		return Invalid(ServerDiscoveryResponseStatus::InvalidJson);
	}
	const auto root = document.object();
	if (!HasRequiredKeys(root, { "version", "mtproto" })
		|| !root.value(u"version"_q).isDouble()
		|| root.value(u"version"_q).toDouble() != 1.
		|| !root.value(u"mtproto"_q).isObject()) {
		return Invalid(ServerDiscoveryResponseStatus::InvalidSchema);
	}
	const auto mtproto = root.value(u"mtproto"_q).toObject();
	if (!HasRequiredKeys(mtproto, { "endpoint", "dc_id", "rsa_spki" })
		|| !mtproto.value(u"endpoint"_q).isString()
		|| !mtproto.value(u"dc_id"_q).isDouble()
		|| !mtproto.value(u"rsa_spki"_q).isString()) {
		return Invalid(ServerDiscoveryResponseStatus::InvalidSchema);
	}

	const auto dcIdValue = mtproto.value(u"dc_id"_q).toDouble();
	if (dcIdValue < 1. || dcIdValue > 1000.
		|| dcIdValue != std::floor(dcIdValue)) {
		return Invalid(ServerDiscoveryResponseStatus::InvalidDcId);
	}

	const auto endpoint = mtproto.value(u"endpoint"_q).toString();
	const auto endpointCheck = CheckServerSelection(endpoint);
	if (!IsPublicDiscoveryEndpoint(endpointCheck)) {
		return Invalid(ServerDiscoveryResponseStatus::UnsafeEndpoint);
	}
	if (selection.explicitPort
		&& endpointCheck.normalizedSelection
			!= selection.normalizedSelection) {
		return Invalid(ServerDiscoveryResponseStatus::EndpointMismatch);
	}

	const auto encoded = mtproto.value(u"rsa_spki"_q).toString().toLatin1();
	if (encoded.isEmpty()) {
		return Invalid(ServerDiscoveryResponseStatus::InvalidKey);
	}
	const auto der = QByteArray::fromBase64(encoded);
	if (der.toBase64() != encoded) {
		return Invalid(ServerDiscoveryResponseStatus::InvalidKey);
	}
	const auto key = ParseSpki(der);
	if (!key) {
		return Invalid(ServerDiscoveryResponseStatus::InvalidKey);
	}

	return {
		.status = ServerDiscoveryResponseStatus::Valid,
		.endpoint = endpointCheck.normalizedSelection,
		.dcId = int(dcIdValue),
		.key = *key,
		.policy = selection.policy,
		.origin = PublicDiscoveryUrl(selection),
	};
}

QByteArray BuildLocalDiscoveryRequest(const QByteArray &nonce) {
	if (nonce.size() != 32) {
		return {};
	}
	return QByteArray(kLocalRequestMagic, 16) + nonce;
}

bool StartLocalDiscoverySocket(
		QTcpSocket &socket,
		const ServerSelectionCheck &selection,
		const QHostAddress &address) {
	if (!selection.valid()
		|| selection.policy != ServerDiscoveryPolicy::LocalDirect
		|| !selection.explicitPort
		|| selection.operationalPort < 1
		|| selection.operationalPort > 65535
		|| address.isNull()
		|| (address.protocol() != QAbstractSocket::IPv4Protocol
			&& address.protocol() != QAbstractSocket::IPv6Protocol)) {
		return false;
	}
	socket.connectToHost(
		address,
		quint16(selection.operationalPort));
	return true;
}

bool StartNextLocalDiscoverySocket(
		QTcpSocket &socket,
		const ServerSelectionCheck &selection,
		const QList<QHostAddress> &addresses,
		int &nextAddress) {
	while (nextAddress >= 0 && nextAddress < addresses.size()) {
		const auto address = addresses.at(nextAddress++);
		if (StartLocalDiscoverySocket(socket, selection, address)) {
			return true;
		}
	}
	return false;
}

bool SendLocalDiscoveryRequest(
		QTcpSocket &socket,
		const QByteArray &request,
		int &writeOffset,
		bool &writeClosed) {
	if (writeClosed) {
		return true;
	}
	if (socket.state() != QAbstractSocket::ConnectedState
		|| request.isEmpty()
		|| writeOffset < 0
		|| writeOffset > request.size()) {
		return false;
	}
	while (writeOffset < request.size()) {
		const auto written = socket.write(
			request.constData() + writeOffset,
			request.size() - writeOffset);
		if (written < 0) {
			return false;
		}
		if (written == 0) {
			return true;
		}
		writeOffset += int(written);
	}
	if (socket.bytesToWrite() > 0) {
		if (!socket.flush()) {
			return false;
		}
		if (socket.bytesToWrite() > 0) {
			return true;
		}
	}

	const auto descriptor = socket.socketDescriptor();
	if (descriptor < 0) {
		return false;
	}
#if defined Q_OS_WIN
	const auto result = ::shutdown(
		static_cast<SOCKET>(descriptor),
		SD_SEND);
#else
	const auto result = ::shutdown(
		static_cast<int>(descriptor),
		SHUT_WR);
#endif
	if (result != 0) {
		return false;
	}
	writeClosed = true;
	return true;
}

bool IsCompleteLocalDiscoveryResponse(const QByteArray &response) {
	constexpr auto kLocalResponsePrefix = 52;
	if (response.size() < kLocalResponsePrefix) {
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
	return response.size() >= kLocalResponsePrefix + int(bodyLength);
}

ServerDiscoveryResult ParseLocalDiscoveryResponse(
		const ServerSelectionCheck &selection,
		const QByteArray &nonce,
		const QByteArray &response) {
	if (!selection.valid()
		|| selection.policy != ServerDiscoveryPolicy::LocalDirect
		|| nonce.size() != 32) {
		return Invalid(ServerDiscoveryResponseStatus::UnsafeEndpoint);
	}
	constexpr auto kPrefix = 16 + 32 + 4;
	constexpr auto kBodyPrefix = 4 + 2;
	if (response.size() < kPrefix + kBodyPrefix
		|| response.size() > kPrefix + kBodyPrefix + kMaxSpkiBytes) {
		return Invalid(ServerDiscoveryResponseStatus::BadFrame);
	}
	if (response.left(16) != QByteArray(kLocalResponseMagic, 16)) {
		return Invalid(ServerDiscoveryResponseStatus::BadFrame);
	}
	if (response.mid(16, 32) != nonce) {
		return Invalid(ServerDiscoveryResponseStatus::NonceMismatch);
	}
	const auto read32 = [](const QByteArray &bytes, int offset) {
		return (quint32(uchar(bytes[offset])) << 24)
			| (quint32(uchar(bytes[offset + 1])) << 16)
			| (quint32(uchar(bytes[offset + 2])) << 8)
			| quint32(uchar(bytes[offset + 3]));
	};
	const auto read16 = [](const QByteArray &bytes, int offset) {
		return (quint16(uchar(bytes[offset])) << 8)
			| quint16(uchar(bytes[offset + 1]));
	};
	const auto bodyLength = read32(response, 48);
	const auto dcId = qint32(read32(response, 52));
	const auto spkiLength = read16(response, 56);
	if (spkiLength < 1 || spkiLength > kMaxSpkiBytes
		|| bodyLength != quint32(6 + spkiLength)
		|| response.size() != 48 + 4 + bodyLength
		|| dcId <= 0 || dcId > 1000) {
		return Invalid(ServerDiscoveryResponseStatus::BadFrame);
	}
	const auto der = response.mid(58, spkiLength);
	const auto key = ParseSpki(der);
	if (!key) {
		return Invalid(ServerDiscoveryResponseStatus::InvalidKey);
	}
	return {
		.status = ServerDiscoveryResponseStatus::Valid,
		.endpoint = selection.normalizedSelection,
		.dcId = dcId,
		.key = *key,
		.policy = selection.policy,
		.origin = u"local:"_q + selection.normalizedSelection,
	};
}

} // namespace MTP
