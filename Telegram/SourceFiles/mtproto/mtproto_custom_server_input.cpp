/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/mtproto_custom_server_input.h"

#include "base/openssl_help.h"

#include <QtNetwork/QHostAddress>

namespace MTP {
namespace {

// The exchange encrypts a fixed 256 byte block with RSA_NO_PADDING, so
// a key of any other size cannot complete it: it would fail much later
// and look like an unreachable server.
constexpr auto kRequiredModulusBits = 2048;

// The whole digest, rendered two bytes to a group, is the 16 groups of
// four hex characters the server logs. Nothing is truncated and nothing
// is reordered: the client's string has to be comparable to the
// server's character by character, or the user cannot check a key at
// all and every legitimate one looks wrong.
constexpr auto kIdentityHexSize = 2 * int(openssl::kSha256Size);
constexpr auto kIdentityGroupBytes = 2;

// A persisted address is read back with a 45 byte bound, the length of
// the longest IPv6 literal, and the bound the endpoint table has always
// had. A longer host would pin for this session and then fail to load,
// so it is refused here, where the user can still change it.
constexpr auto kMaxHostSize = 45;

constexpr auto kMaxPort = 65535;

[[nodiscard]] bool IsAsciiDigit(QChar ch) {
	const auto code = ch.unicode();
	return (code >= '0') && (code <= '9');
}

// Letters, digits and hyphens, in dot-separated labels of one to 63
// characters that neither start nor end with a hyphen.
[[nodiscard]] bool ValidHostname(const QString &host) {
	constexpr auto kMaxLabelSize = 63;

	auto labelSize = 0;
	for (auto i = 0, count = int(host.size()); i != count; ++i) {
		const auto code = host[i].unicode();
		if (code == '.') {
			if (!labelSize) {
				return false;
			}
			labelSize = 0;
			continue;
		}
		const auto allowed = (code >= 'a' && code <= 'z')
			|| (code >= 'A' && code <= 'Z')
			|| (code >= '0' && code <= '9')
			|| (code == '-');
		if (!allowed) {
			return false;
		} else if (code == '-'
			&& (!labelSize
				|| (i + 1 == count)
				|| (host[i + 1].unicode() == '.'))) {
			return false;
		} else if (++labelSize > kMaxLabelSize) {
			return false;
		}
	}
	return (labelSize > 0);
}

// The 64 hex characters of an identity, without the dashes, whitespace
// and letter case the user's copy of it may carry. Empty for anything
// that is not an identity at all, including a truncated one: a prefix
// that compares equal is exactly the "close enough" answer this must
// not give.
[[nodiscard]] QString NormalizedIdentity(const QString &value) {
	auto result = QString();
	result.reserve(kIdentityHexSize);
	for (const auto ch : value) {
		if (ch == QChar::fromLatin1('-') || ch.isSpace()) {
			continue;
		}
		const auto lower = ch.toLower();
		const auto code = lower.unicode();
		const auto hex = (code >= '0' && code <= '9')
			|| (code >= 'a' && code <= 'f');
		if (!hex || result.size() == kIdentityHexSize) {
			return QString();
		}
		result.append(lower);
	}
	return (result.size() == kIdentityHexSize) ? result : QString();
}

} // namespace

ServerKeyCheck CheckServerKey(const QString &pem) {
	const auto utf8 = pem.trimmed().toUtf8();
	if (utf8.isEmpty()) {
		return { .status = ServerKeyStatus::Empty };
	}
	auto key = details::RSAPublicKey(bytes::make_span(utf8));
	if (!key.valid()) {
		return { .status = ServerKeyStatus::Unreadable };
	} else if (key.modulusBits() != kRequiredModulusBits) {
		return { .status = ServerKeyStatus::BadModulusSize };
	}
	auto identity = ServerKeyIdentity(key);
	if (identity.isEmpty()) {
		// A key we cannot name is a key the user cannot check against
		// the server, and an unchecked key is the failure this input
		// exists to prevent, so it does not pass as a usable one.
		return { .status = ServerKeyStatus::Unreadable };
	}
	return {
		.status = ServerKeyStatus::Valid,
		.key = std::move(key),
		.identity = std::move(identity),
	};
}

QString ServerKeyIdentity(const details::RSAPublicKey &key) {
	if (!key.valid()) {
		return QString();
	}
	const auto der = key.getSubjectPublicKeyInfo();
	if (der.empty()) {
		return QString();
	}
	const auto digest = openssl::Sha256(bytes::make_span(der));
	const auto count = int(digest.size());

	Assert(count == int(openssl::kSha256Size));

	const auto digits = "0123456789abcdef";
	auto result = QString();
	result.reserve(kIdentityHexSize + (count / kIdentityGroupBytes) - 1);
	for (auto i = 0; i != count; ++i) {
		if (i && !(i % kIdentityGroupBytes)) {
			result.append(QChar::fromLatin1('-'));
		}
		const auto byte = gsl::to_integer<uchar>(digest[i]);
		result.append(QChar::fromLatin1(digits[byte >> 4]));
		result.append(QChar::fromLatin1(digits[byte & 0x0F]));
	}
	return result;
}

bool ServerKeyIdentityMatches(
		const QString &typed,
		const QString &computed) {
	const auto left = NormalizedIdentity(typed);
	const auto right = NormalizedIdentity(computed);
	return !left.isEmpty() && (left == right);
}

ServerEndpointCheck CheckServerEndpoint(const QString &value) {
	const auto trimmed = value.trimmed();
	if (trimmed.isEmpty()) {
		return { .status = ServerEndpointStatus::Empty };
	}

	const auto bracketed = trimmed.startsWith(QChar::fromLatin1('['));
	auto hostText = QString();
	auto portText = QString();
	if (bracketed) {
		const auto close = trimmed.indexOf(QChar::fromLatin1(']'));
		if (close < 0) {
			return { .status = ServerEndpointStatus::BadHost };
		}
		hostText = trimmed.mid(1, close - 1);
		const auto rest = trimmed.mid(close + 1);
		if (rest.isEmpty()) {
			return { .status = ServerEndpointStatus::NoPort };
		} else if (!rest.startsWith(QChar::fromLatin1(':'))) {
			return { .status = ServerEndpointStatus::BadPort };
		}
		portText = rest.mid(1);
	} else {
		const auto colon = trimmed.lastIndexOf(QChar::fromLatin1(':'));
		if (colon < 0) {
			return { .status = ServerEndpointStatus::NoPort };
		} else if (trimmed.indexOf(QChar::fromLatin1(':')) != colon) {
			// More than one colon and no brackets is an IPv6 address,
			// with or without a port, and there is no telling which.
			// Splitting at the last colon would silently pin a prefix
			// of the address the user meant.
			return { .status = ServerEndpointStatus::UnbracketedIPv6 };
		}
		hostText = trimmed.mid(0, colon);
		portText = trimmed.mid(colon + 1);
	}

	// toInt() would take "+443" and "  443"; a port is digits.
	const auto notDigit = [](QChar ch) { return !IsAsciiDigit(ch); };
	if (portText.isEmpty()
		|| (std::find_if(portText.begin(), portText.end(), notDigit)
			!= portText.end())) {
		return { .status = ServerEndpointStatus::BadPort };
	}
	const auto port = portText.toInt();
	if (port < 1 || port > kMaxPort) {
		return { .status = ServerEndpointStatus::BadPort };
	}

	if (hostText.isEmpty()) {
		return { .status = ServerEndpointStatus::EmptyHost };
	} else if (hostText.size() > kMaxHostSize) {
		return { .status = ServerEndpointStatus::HostTooLong };
	}
	auto address = QHostAddress();
	const auto literal = address.setAddress(hostText);
	if (bracketed && !literal) {
		// Brackets say "this is an IP literal", so a hostname in them
		// is a typo rather than a second way to write a hostname.
		return { .status = ServerEndpointStatus::BadHost };
	} else if (!literal && !ValidHostname(hostText)) {
		return { .status = ServerEndpointStatus::BadHost };
	}
	return {
		.status = ServerEndpointStatus::Valid,
		.host = hostText.toStdString(),
		.port = port,
		.ipv6 = (literal
			&& (address.protocol() == QAbstractSocket::IPv6Protocol)),
	};
}

} // namespace MTP
