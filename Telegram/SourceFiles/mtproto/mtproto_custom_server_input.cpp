/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/mtproto_custom_server_input.h"

#include "base/algorithm.h"
#include "base/openssl_help.h"

#include <QtNetwork/QHostAddress>

namespace MTP {
namespace {

struct BIODeleter {
	void operator()(BIO *value) {
		BIO_free(value);
	}
};

struct PkeyDeleter {
	void operator()(EVP_PKEY *value) {
		EVP_PKEY_free(value);
	}
};

// A public key PEM can carry legacy encryption headers (Proc-Type,
// DEK-Info). With a null callback OpenSSL falls back to PEM_def_callback
// and prompts on stdin or the tty, which hangs a client started from a
// terminal. Returning -1 refuses the prompt and yields no key.
[[nodiscard]] int NoPassword(char *, int, int, void *) {
	return -1;
}

// A private key frame: a "-----BEGIN <label>-----" line whose label
// contains "PRIVATE KEY". The check is a frame check, not a parse:
// the validator must not decode private key material, so it never
// touches the base64, and a mangled body still says what the user
// pasted. A paste containing the frame is refused, even if a public
// key also parses out of the same text. The BEGIN line is the answer
// on its own, so the check is one linear pass: no search for the
// matching END, and the cost does not grow with the number of known
// names.
[[nodiscard]] bool HasPrivateFrame(const QByteArray &text) {
	const auto kBegin = QByteArray("-----BEGIN ");
	const auto kPrivate = QByteArray("PRIVATE KEY");
	const auto kDashes = QByteArray("-----");

	auto pos = 0;
	while ((pos = text.indexOf(kBegin, pos)) >= 0) {
		const auto labelStart = pos + kBegin.size();
		const auto labelEnd = text.indexOf(kDashes, labelStart);
		if (labelEnd < 0) {
			break;
		}
		const auto label = text.mid(labelStart, labelEnd - labelStart);
		if (label.contains(kPrivate)) {
			return true;
		}
		pos = labelEnd + kDashes.size();
	}
	return false;
}

// The algorithm of a readable public key, or -1 when the input is not
// a public key at all. A public key costs nothing to decode, so the
// parsed algorithm id is the discriminator the label cannot give:
// every algorithm's SPKI block carries the same "BEGIN PUBLIC KEY"
// label.
[[nodiscard]] int PublicKeyAlgorithm(bytes::const_span pem) {
	const auto bio = std::unique_ptr<BIO, BIODeleter>(
		BIO_new_mem_buf(
			const_cast<gsl::byte *>(pem.data()),
			pem.size()));
	const auto pkey = std::unique_ptr<EVP_PKEY, PkeyDeleter>(
		PEM_read_bio_PUBKEY(bio.get(), nullptr, NoPassword, nullptr));
	return pkey ? EVP_PKEY_base_id(pkey.get()) : -1;
}

// A paste is a key the user typed, and a key the user typed fits in a
// screen. Anything over this is not a key, and the bound keeps the
// length out of the int range the BIO length parameter cannot carry.
// The room is for a 4096 bit key and its armor, with margin.
constexpr auto kMaxKeySize = 8192;

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
	const auto text = QByteArray::fromRawData(
		reinterpret_cast<const char *>(utf8.data()),
		utf8.size());
	// The private frame is checked before anything else, and it refuses
	// on its own: a paste that carries somebody's private key is not a
	// usable public key, even if one also parses out of the same text.
	// The check reads the frame, not the key, so nothing of the secret
	// is decoded, logged, stored or returned, and it is not parsing, so
	// it belongs ahead of the size bound that gates the parse path.
	if (HasPrivateFrame(text)) {
		return { .status = ServerKeyStatus::PrivateKey };
	}
	if (utf8.size() > kMaxKeySize) {
		return { .status = ServerKeyStatus::Unreadable };
	}
	auto key = details::RSAPublicKey(bytes::make_span(utf8));
	if (!key.valid()) {
		// A readable public key that is not RSA is a different mistake
		// from not a key at all, and the algorithm id is what tells
		// them apart.
		return (PublicKeyAlgorithm(bytes::make_span(utf8)) >= 0)
			? ServerKeyCheck{ .status = ServerKeyStatus::NotRsaKey }
			: ServerKeyCheck{ .status = ServerKeyStatus::Unreadable };
	} else if (key.modulusBits() != kRequiredModulusBits) {
		return {
			.status = ServerKeyStatus::BadModulusSize,
			.modulusBits = key.modulusBits(),
		};
	}
	auto identity = ServerKeyIdentity(key);
	if (identity.isEmpty()) {
		return { .status = ServerKeyStatus::InternalError };
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

bool LooksLikeKeyId(const QString &s) {
	auto hexCount = 0;
	for (const auto ch : s) {
		if (ch == QChar::fromLatin1('-')) continue;
		if (!((ch >= QChar::fromLatin1('0') && ch <= QChar::fromLatin1('9'))
			|| (ch >= QChar::fromLatin1('a') && ch <= QChar::fromLatin1('f'))
			|| (ch >= QChar::fromLatin1('A') && ch <= QChar::fromLatin1('F')))) {
			return false;
		}
		++hexCount;
	}
	return hexCount == 64;
}

QString ExtractKeyId(const QString &text) {
	const auto needle = u"key_id="_q;
	const auto pos = text.indexOf(needle);
	if (pos < 0) {
		return text.trimmed();
	}
	// For the logfmt form, collect hex and dashes, crossing newlines only
	// when the token that follows carries no '=' before its first
	// whitespace. A logfmt field always has one (name=value); a wrapped
	// continuation of a hex value never can. Space and tab are unambiguous
	// logfmt field separators and always stop collection.
	auto i = pos + needle.size();
	const auto size = text.size();
	const auto quoted = (i < size)
		&& (text[i] == QChar::fromLatin1('"'));
	if (quoted) {
		++i;
	}
	auto result = QString();
	result.reserve(79); // 64 hex + up to 15 dashes
	auto hexCount = 0;
	for (; i < size && hexCount < kIdentityHexSize; ++i) {
		const auto ch = text[i];
		if (ch == QChar::fromLatin1('\n') || ch == QChar::fromLatin1('\r')) {
			// Look ahead: if the next non-whitespace token has '=' before
			// its first whitespace it is a logfmt field — stop. Otherwise
			// it is a wrapped continuation of the hex value — keep going.
			auto j = i + 1;
			while (j < size && text[j].isSpace()) {
				++j;
			}
			auto k = j;
			while (k < size
					&& !text[k].isSpace()
					&& text[k] != QChar::fromLatin1('=')) {
				++k;
			}
			if (k < size && text[k] == QChar::fromLatin1('=')) {
				break; // next token is a logfmt field
			}
			continue;
		}
		if (ch.isSpace()) {
			break; // space or tab is a logfmt field separator
		}
		if (quoted && ch == QChar::fromLatin1('"')) {
			break;
		}
		if (ch == QChar::fromLatin1('-')) {
			result += ch;
			continue;
		}
		const auto code = ch.toLower().unicode();
		const auto isHex = (code >= '0' && code <= '9')
			|| (code >= 'a' && code <= 'f');
		if (!isHex) {
			break;
		}
		result += ch;
		++hexCount;
	}
	return result;
}

IdentityLayout ChooseIdentityLayout(
		int innerWidth,
		int advance13,
		int advance12) {
	if (advance13 <= innerWidth) return {.pixelSize = 13, .fits = true};
	if (advance12 <= innerWidth) return {.pixelSize = 12, .fits = true};
	return {.pixelSize = 12, .fits = false};
}

AuthKeyFailureAction ClassifyAuthKeyFailure(
		details::DcKeyError error,
		DcType dcType) {
	if (dcType == DcType::Cdn) {
		// A CDN DC missing its keys asks for CDN config, it does not
		// fail the pin (MAIN-313 owns CDN key handling).
		return (error == details::DcKeyError::UnknownPublicKey)
			? AuthKeyFailureAction::RequestCdnConfig
			: AuthKeyFailureAction::Retry;
	}
	return (error == details::DcKeyError::UnknownPublicKey)
		? AuthKeyFailureAction::ReportKeyMismatch
		: AuthKeyFailureAction::Retry;
}

std::optional<PinnedServerFailure> CheckPinnedServerConfig(
		int thisDc,
		const std::vector<int> &advertisedDcs,
		const CustomServer &pinned) {
	if (pinned.empty()) {
		return std::nullopt;
	}
	if (thisDc != pinned.dcId) {
		return std::make_optional(PinnedServerFailure::DcIdMismatch);
	}
	// A server may omit dc options entirely and still be the right
	// one; an advertisement that exists has to carry the pin.
	if (!advertisedDcs.empty()
		&& !base::contains(advertisedDcs, pinned.dcId)) {
		return std::make_optional(PinnedServerFailure::DcIdMismatch);
	}
	return std::nullopt;
}

} // namespace MTP
