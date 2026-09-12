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

// Why a server enrollment artifact was refused. Every value is a distinct
// input correction or a distinct key-processing outcome for the caller.
enum class ServerEnrollmentStatus {
	Valid,
	MissingEndpoint,
	MissingKey,
	MultipleEndpoints,
	MultipleKeys,
	TruncatedEnvelope,
	UnparseableEnvelope,
	TrailingContent,
	EndpointNoPort,
	EndpointBadPort,
	EndpointEmptyHost,
	EndpointBadHost,
	EndpointHostTooLong,
	EndpointUnbracketedIPv6,
	UnreadableKey,
	PrivateKey,
	NotRsaKey,
	BadModulusSize,
	InternalKeyError,
};

// The result of parsing one complete, validated enrollment artifact.
// Anything other than Valid leaves every usable output empty.
struct ServerEnrollmentCheck {
	ServerEnrollmentStatus status = ServerEnrollmentStatus::UnparseableEnvelope;
	std::string endpoint;
	details::RSAPublicKey key;
	QString identity;
	int modulusBits = 0;

	[[nodiscard]] bool valid() const {
		return (status == ServerEnrollmentStatus::Valid);
	}
	[[nodiscard]] explicit operator bool() const {
		return valid();
	}
};

// Stable identifiers for diagnostics and exhaustive downstream mappings.
[[nodiscard]] const char *ServerEnrollmentStatusName(
	ServerEnrollmentStatus status);

// Parse the one-paste enrollment format documented in docs/server_enrollment.md.
[[nodiscard]] ServerEnrollmentCheck CheckServerEnrollment(
	const QString &artifact);

} // namespace MTP
