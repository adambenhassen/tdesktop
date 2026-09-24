/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_rsa_public_key.h"

#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtNetwork/QHostAddress>

#include <optional>

class QNetworkRequest;
class QTcpSocket;

namespace MTP {

// The policy is selected from the normalized text before any socket or DNS
// operation. It is persisted with the binding and cannot be changed by a
// discovery response.
enum class ServerDiscoveryPolicy : uchar {
	Legacy,
	PublicHttps,
	LocalDirect,
};

// Limits simultaneous automatic discovery work across all account flows in
// this process. Ownership is released when the token leaves scope.
class ServerDiscoveryAttempt final {
public:
	[[nodiscard]] static std::optional<ServerDiscoveryAttempt> Acquire();

	ServerDiscoveryAttempt(const ServerDiscoveryAttempt &) = delete;
	ServerDiscoveryAttempt &operator=(const ServerDiscoveryAttempt &) = delete;
	ServerDiscoveryAttempt(ServerDiscoveryAttempt &&other) noexcept;
	ServerDiscoveryAttempt &operator=(ServerDiscoveryAttempt &&other) noexcept;
	~ServerDiscoveryAttempt();

private:
	explicit ServerDiscoveryAttempt(bool held) : _held(held) {
	}

	bool _held = false;
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

// Whether an address is globally routable unicast. This deliberately remains
// separate from CheckServerSelection(), where every IP literal is local-direct
// because it has no DNS name that WebPKI can authenticate.
[[nodiscard]] bool IsPublicAddress(const QHostAddress &address);
// Whether an address is safe for public discovery from the typed HTTPS origin.
// MagicDNS origins also allow addresses in the two Tailscale ranges.
[[nodiscard]] bool IsPublicDiscoveryAddress(
	const ServerSelectionCheck &origin,
	const QHostAddress &address);
[[nodiscard]] std::optional<QHostAddress> FirstSafePublicDiscoveryAddress(
	const ServerSelectionCheck &origin,
	const QList<QHostAddress> &addresses);

// A delegated public endpoint must be an explicit-port public DNS name or a
// safe IP literal for the selected HTTPS origin. IP literals remain
// local-direct when they are user selections, but a verified document may
// delegate to a public or Tailscale address.
[[nodiscard]] bool IsPublicDiscoveryEndpoint(
	const ServerSelectionCheck &endpoint,
	const ServerSelectionCheck &origin);

// This URL is derived only from a valid public selection. It never carries a
// query, fragment, credentials, or a user-supplied path.
[[nodiscard]] QString PublicDiscoveryUrl(
	const ServerSelectionCheck &selection);

// Apply the network policy to every public discovery request, including
// retries. Cookies are intentionally managed by the application, not Qt.
void ConfigurePublicDiscoveryRequest(QNetworkRequest &request);

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

// Start a local/direct socket only after the selected host has resolved to a
// concrete IPv4 or IPv6 address. The caller owns the socket and its signals.
[[nodiscard]] bool StartLocalDiscoverySocket(
	QTcpSocket &socket,
	const ServerSelectionCheck &selection,
	const QHostAddress &address);

[[nodiscard]] bool StartNextLocalDiscoverySocket(
	QTcpSocket &socket,
	const ServerSelectionCheck &selection,
	const QList<QHostAddress> &addresses,
	int &nextAddress);

[[nodiscard]] bool IsCompleteLocalDiscoveryResponse(
	const QByteArray &response);

[[nodiscard]] ServerDiscoveryResult ParseLocalDiscoveryResponse(
	const ServerSelectionCheck &selection,
	const QByteArray &nonce,
	const QByteArray &response);

} // namespace MTP
