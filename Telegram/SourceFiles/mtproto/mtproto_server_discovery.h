/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_rsa_public_key.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtNetwork/QHostAddress>

namespace MTP {

// The policy is selected from the normalized text before any socket or DNS
// operation. It is persisted with the binding and cannot be changed by a
// discovery response.
enum class ServerDiscoveryPolicy : uchar {
	Legacy,
	PublicHttps,
	LocalDirect,
};

enum class ServerSelectionStatus {
	Valid,
	Empty,
	NoPort,
	BadPort,
	EmptyHost,
	BadHost,
	HostTooLong,
	UnbracketedIPv6,
	InvalidSpecialAddress,
};

struct ServerSelectionCheck {
	ServerSelectionStatus status = ServerSelectionStatus::Empty;
	QString host;
	QString normalizedSelection;
	int requestedPort = 0;
	int operationalPort = 0;
	bool ipv6 = false;
	bool explicitPort = false;
	ServerDiscoveryPolicy policy = ServerDiscoveryPolicy::PublicHttps;

	[[nodiscard]] bool valid() const {
		return status == ServerSelectionStatus::Valid;
	}
	[[nodiscard]] explicit operator bool() const {
		return valid();
	}
};

[[nodiscard]] ServerSelectionCheck CheckServerSelection(
	const QString &value);

// A resolved address is safe for the public HTTPS delegation route only when
// it is a globally routable IPv4 or IPv6 address. This deliberately remains
// separate from CheckServerSelection(), where every IP literal is local-direct
// because it has no DNS name that WebPKI can authenticate.
[[nodiscard]] bool IsPublicAddress(const QHostAddress &address);

// A delegated public endpoint must be an explicit-port public DNS name or a
// globally routable IP literal. IP literals remain local-direct when they
// are user selections, but a verified document may delegate to a public one.
[[nodiscard]] bool IsPublicDiscoveryEndpoint(
	const ServerSelectionCheck &selection);

// This URL is derived only from a valid public selection. It never carries a
// query, fragment, credentials, or a user-supplied path.
[[nodiscard]] QString PublicDiscoveryUrl(
	const ServerSelectionCheck &selection);

enum class ServerDiscoveryResponseStatus {
	Valid,
	InvalidJson,
	InvalidSchema,
	InvalidKey,
	InvalidDcId,
	EndpointMismatch,
	UnsafeEndpoint,
	BadFrame,
	NonceMismatch,
};

struct ServerDiscoveryResult {
	ServerDiscoveryResponseStatus status
		= ServerDiscoveryResponseStatus::InvalidJson;
	QString endpoint;
	// A public delegated endpoint is resolved and classified before it is
	// committed. The selected address is kept separately so later MTProto
	// connections do not perform an unvetted DNS lookup again.
	QString resolvedAddress;
	int dcId = 0;
	details::RSAPublicKey key;
	ServerDiscoveryPolicy policy = ServerDiscoveryPolicy::PublicHttps;
	QString origin;

	[[nodiscard]] bool valid() const {
		return status == ServerDiscoveryResponseStatus::Valid;
	}
	[[nodiscard]] explicit operator bool() const {
		return valid();
	}
};

// Parse the exact version-1 response served by the public discovery URL.
// The selected policy remains authoritative; endpoint delegation can only
// produce another public endpoint. When the user typed a public host:port,
// the returned endpoint must equal that normalized pair.
[[nodiscard]] ServerDiscoveryResult ParsePublicDiscoveryResponse(
	const ServerSelectionCheck &selection,
	const QByteArray &body);

// MAIN-736 local/direct preflight framing.
[[nodiscard]] QByteArray BuildLocalDiscoveryRequest(const QByteArray &nonce);

[[nodiscard]] ServerDiscoveryResult ParseLocalDiscoveryResponse(
	const ServerSelectionCheck &selection,
	const QByteArray &nonce,
	const QByteArray &response);

} // namespace MTP
