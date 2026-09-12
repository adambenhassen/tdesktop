/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_rsa_public_key.h"

#include <QtCore/QString>

#include <functional>
#include <string>

class QKeyEvent;

namespace MTP {

enum class ServerKeyStatus;

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

// Map an existing key validator verdict to the corresponding enrollment
// reason. This boundary is separately testable because InternalError can
// only be produced by a failure while re-encoding an otherwise valid key.
[[nodiscard]] ServerEnrollmentStatus ServerEnrollmentStatusFromKeyStatus(
	ServerKeyStatus status);

// Parse the one-paste enrollment format documented in docs/server_enrollment.md.
[[nodiscard]] ServerEnrollmentCheck CheckServerEnrollment(
	const QString &artifact);

// Run the enrollment side effects in their security order. A failed pin
// persistence step must not start network/auth activity, and the first
// connection is allowed only after the pin is persisted. The optional
// rollback restores staged in-memory state when persistence fails.
[[nodiscard]] bool CommitServerEnrollment(
	const std::function<bool()> &setPin,
	const std::function<bool()> &persistPin,
	const std::function<void()> &resume,
	const std::function<void()> &rollbackPin = {});

// The shell handles activation keys globally. The enrollment step consumes
// these keys when they bubble from non-action controls so they cannot submit
// the confirmation accidentally.
[[nodiscard]] bool IsServerEnrollmentActivationKey(int key);
[[nodiscard]] bool ConsumeServerEnrollmentActivationKey(QKeyEvent &event);

} // namespace MTP
