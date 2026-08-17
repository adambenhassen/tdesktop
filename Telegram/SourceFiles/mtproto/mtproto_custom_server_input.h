/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_rsa_public_key.h"

#include <QtCore/QString>
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
};

// The outcome of checking a pasted key. Anything other than Valid
// leaves both the key and the identity empty: a caller cannot pick up
// half of a refused key by accident.
struct ServerKeyCheck {
	ServerKeyStatus status = ServerKeyStatus::Empty;
	details::RSAPublicKey key;
	QString identity;

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

} // namespace MTP
