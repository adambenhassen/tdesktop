/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_dc_key_creator.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/mtproto_dc_options.h"

#include <QtCore/QString>
#include <optional>
#include <string>

namespace MTP {

// Why a pasted RSA public key was refused. Each value is a different
// message to the user and a different thing to do about it, so they
// must not collapse into one "bad key".
enum class ServerKeyStatus {
	Valid,
	Empty,
	Unreadable, // A PEM block we cannot read as a key of any kind.
	PrivateKey, // A private key frame: the user is holding the server's
		// secret, not the public half to paste here.
	NotRsaKey, // A readable public key, but not an RSA one.
	BadModulusSize, // A readable RSA key, of a size we cannot talk to.
	InternalError, // A key that parsed but whose DER encoding failed —
		// internal error, not a user mistake. Rare: only an allocation
		// failure reaches it.
};

// The outcome of checking a pasted key. Anything other than Valid
// leaves both the key and the identity empty: a caller cannot pick up
// half of a refused key by accident.
struct ServerKeyCheck {
	ServerKeyStatus status = ServerKeyStatus::Empty;
	details::RSAPublicKey key;
	QString identity;
	int modulusBits = 0; // Set when status == BadModulusSize.

	[[nodiscard]] bool valid() const {
		return (status == ServerKeyStatus::Valid);
	}
	[[nodiscard]] explicit operator bool() const {
		return valid();
	}

};

// Read an RSA public key the user pasted, in either PEM form:
// "-----BEGIN PUBLIC KEY-----" or "-----BEGIN RSA PUBLIC KEY-----".
[[nodiscard]] ServerKeyCheck CheckServerKey(const QString &pem);

// The key's identity: the SHA-256 of its DER SubjectPublicKeyInfo
// encoding, as 64 lowercase hex characters in 16 dash-separated groups
// of four. Byte-identical to the key_id the server logs at startup, so
// the user can compare the two by eye. Empty if the key is invalid.
[[nodiscard]] QString ServerKeyIdentity(const details::RSAPublicKey &key);

// Whether what the user typed names the same key as `computed`. Dashes,
// whitespace and letter case in either value are ignored; anything else
// is a mismatch. This answer is all-or-nothing on purpose: a partial
// one would invite the user to accept a key on a matching prefix.
[[nodiscard]] bool ServerKeyIdentityMatches(
	const QString &typed,
	const QString &computed);

// What the key-check step's comparison field says: the outcome of
// putting the key_id the user typed next to the identity computed from
// the pasted key. Pass an empty `computed` when no valid key was
// entered; nothing can then count as a match.
enum class KeyIdCompare {
	None, // Nothing typed yet: not a failed check, just not started.
	Match,
	Mismatch,
	Unreadable, // Something typed, but it is not a readable key_id.
};

[[nodiscard]] KeyIdCompare CompareKeyId(
	const QString &typed,
	const QString &computed);

// Whether the flow may advance for this comparison outcome. None
// advances (the user did not start checking yet) and Match advances;
// Mismatch blocks, and so does Unreadable: an unreadable entry means
// the user compared nothing at all, which is the state the step exists
// to prevent.
[[nodiscard]] bool KeyIdCompareAllowsAdvance(KeyIdCompare compare);

// Why an endpoint the user typed was refused.
enum class ServerEndpointStatus {
	Valid,
	Empty,
	NoPort,
	BadPort,
	EmptyHost,
	BadHost,
	HostTooLong,
	UnbracketedIPv6, // An IPv6 address has to be written [address]:port.
};

// The outcome of checking an endpoint. Anything other than Valid leaves
// the host empty and the port zero.
struct ServerEndpointCheck {
	ServerEndpointStatus status = ServerEndpointStatus::Empty;
	std::string host;
	int port = 0;
	// True when the host is an IPv6 literal, which the endpoint this
	// becomes has to be flagged as.
	bool ipv6 = false;

	[[nodiscard]] bool valid() const {
		return (status == ServerEndpointStatus::Valid);
	}
	[[nodiscard]] explicit operator bool() const {
		return valid();
	}

};

// Read a "host:port" endpoint the user typed. The host is an IP literal
// or a hostname; an IPv6 literal is written in brackets, as "[::1]:443".
[[nodiscard]] ServerEndpointCheck CheckServerEndpoint(const QString &value);

// Whether a string looks like a key_id the server logged: exactly 64
// hex characters, optionally grouped by dashes every 4 chars. Any
// other character (including a surrounding quote) is not a key_id.
[[nodiscard]] bool LooksLikeKeyId(const QString &s);

// If text is a logfmt token of the form key_id=<value>, return the
// value (stripping surrounding quotes if present); otherwise return
// text.trimmed(). Lets the user paste a whole server log line.
[[nodiscard]] QString ExtractKeyId(const QString &text);

// Why a pinned endpoint failed after the connection came up. Neither
// value is a transient network problem and neither fixes itself on
// retry, so both have to reach the user instead of a reconnect loop.
// Each is a different message and a different thing to do about it.
enum class PinnedServerFailure {
	KeyMismatch, // The endpoint answered the auth-key exchange with an
		// RSA public key this account was not given: either the pasted
		// key is wrong or something on the path answers for the server.
	DcIdMismatch, // The connected server reports a different DC id
		// than the one pinned for this account.
};

// What a failed auth-key exchange says about the pin. Only a pinned
// DC answering with a public key this account was not given is a pin
// failure: on an unpinned account there is no key-identity question,
// and every error keeps its existing retry behaviour. A CDN DC
// refuses differently (MAIN-313), pinned or not.
enum class AuthKeyFailureAction {
	Retry, // Not a pin problem: keep the existing restart-on-failure
		// behaviour for this error.
	RequestCdnConfig, // A CDN DC missing its keys asks for CDN config.
	ReportKeyMismatch, // The pinned endpoint answered with an unknown
		// public key: report and stop.
};
[[nodiscard]] AuthKeyFailureAction ClassifyAuthKeyFailure(
	details::DcKeyError error,
	DcType dcType,
	bool customServerPinned);

// What the first config response from the connected server says about
// the endpoint pinned for this account. The server confirms the pin by
// naming it as its own DC (thisDc) and, when it advertises any dc
// options at all, by listing the pinned id among them; either refusal
// means the account would drop its only endpoint once the advertised
// id took over. Nothing pinned returns empty.
[[nodiscard]] std::optional<PinnedServerFailure> CheckPinnedServerConfig(
	int thisDc,
	const std::vector<int> &advertisedDcs,
	const CustomServer &pinned);

// Layout decision for the identity display: which pixel size to use and
// whether both rows fit. advance13 and advance12 are the horizontal pixel
// widths of row 1 at 13px and 12px respectively. Callers compute those
// with QFontMetrics before calling so the decision is testable without a
// widget.
struct IdentityLayout {
	int pixelSize = 13;
	bool fits = true;
};
[[nodiscard]] IdentityLayout ChooseIdentityLayout(
	int innerWidth,
	int advance13,
	int advance12);

} // namespace MTP
