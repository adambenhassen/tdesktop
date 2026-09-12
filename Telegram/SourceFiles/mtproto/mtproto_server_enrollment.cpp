/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/mtproto_server_enrollment.h"

#include "base/openssl_help.h"
#include "mtproto/mtproto_custom_server_input.h"

#include <QtCore/QByteArray>
#include <QtCore/Qt>
#include <QtCore/QStringList>
#include <QtGui/QKeyEvent>
#include <QtNetwork/QHostAddress>

#include <optional>
#include <utility>

namespace MTP {
namespace {

constexpr auto kHeader = "telegramd-enrollment-v1";
constexpr auto kEndpointPrefix = "endpoint=";
constexpr auto kKeyBegin = "public-key-begin";
constexpr auto kKeyEnd = "public-key-end";
constexpr auto kChecksumPrefix = "checksum=sha256:";
constexpr auto kFooter = "telegramd-enrollment-end";

// A 2048-bit PEM and its framing fit well below this bound. Keeping the
// entire paste bounded prevents a malformed artifact from becoming an
// unbounded parsing allocation.
constexpr auto kMaxArtifactSize = 16 * 1024;

[[nodiscard]] ServerEnrollmentCheck Failure(
		ServerEnrollmentStatus status,
		int modulusBits = 0) {
	return {
		.status = status,
		.modulusBits = modulusBits,
	};
}

[[nodiscard]] std::optional<QString> NormalizeLineEndings(
		const QString &artifact) {
	auto result = artifact.trimmed();
	if (result.size() > kMaxArtifactSize) {
		return std::nullopt;
	}
	result.replace(u"\r\n"_q, u"\n"_q);
	if (result.contains(QChar::fromLatin1('\r'))) {
		return std::nullopt;
	}
	return result;
}

[[nodiscard]] bool IsPemKeyBegin(const QString &line) {
	return line.startsWith(u"-----BEGIN "_q)
		&& line.endsWith(u"-----"_q)
		&& line.contains(u"KEY"_q);
}

[[nodiscard]] bool IsPemKeyEnd(const QString &line) {
	return line.startsWith(u"-----END "_q)
		&& line.endsWith(u"-----"_q)
		&& line.contains(u"KEY"_q);
}

[[nodiscard]] bool IsPemPrivateKeyBegin(const QString &line) {
	return IsPemKeyBegin(line) && line.contains(u"PRIVATE KEY"_q);
}

[[nodiscard]] ServerEnrollmentStatus EndpointFailureStatus(
		ServerEndpointStatus status) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch-enum"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(4:4062)
#pragma warning(error:4062)
#endif // __GNUC__ || __clang__ || _MSC_VER
	switch (status) {
	case ServerEndpointStatus::Empty:
		return ServerEnrollmentStatus::MissingEndpoint;
	case ServerEndpointStatus::NoPort:
		return ServerEnrollmentStatus::EndpointNoPort;
	case ServerEndpointStatus::BadPort:
		return ServerEnrollmentStatus::EndpointBadPort;
	case ServerEndpointStatus::EmptyHost:
		return ServerEnrollmentStatus::EndpointEmptyHost;
	case ServerEndpointStatus::BadHost:
		return ServerEnrollmentStatus::EndpointBadHost;
	case ServerEndpointStatus::HostTooLong:
		return ServerEnrollmentStatus::EndpointHostTooLong;
	case ServerEndpointStatus::UnbracketedIPv6:
		return ServerEnrollmentStatus::EndpointUnbracketedIPv6;
	case ServerEndpointStatus::Valid:
		return ServerEnrollmentStatus::UnparseableEnvelope;
	}
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif // __GNUC__ || __clang__ || _MSC_VER
	return ServerEnrollmentStatus::UnparseableEnvelope;
}

[[nodiscard]] ServerEnrollmentStatus KeyFailureStatus(
		ServerKeyStatus status) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch-enum"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(4:4062)
#pragma warning(error:4062)
#endif // __GNUC__ || __clang__ || _MSC_VER
	switch (status) {
	case ServerKeyStatus::Empty:
	case ServerKeyStatus::Unreadable:
		return ServerEnrollmentStatus::UnreadableKey;
	case ServerKeyStatus::PrivateKey:
		return ServerEnrollmentStatus::PrivateKey;
	case ServerKeyStatus::NotRsaKey:
		return ServerEnrollmentStatus::NotRsaKey;
	case ServerKeyStatus::BadModulusSize:
		return ServerEnrollmentStatus::BadModulusSize;
	case ServerKeyStatus::InternalError:
		return ServerEnrollmentStatus::InternalKeyError;
	case ServerKeyStatus::Valid:
		return ServerEnrollmentStatus::UnparseableEnvelope;
	}
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif // __GNUC__ || __clang__ || _MSC_VER
	return ServerEnrollmentStatus::UnparseableEnvelope;
}

[[nodiscard]] QString NormalizeEndpoint(
		const ServerEndpointCheck &check) {
	const auto host = QString::fromStdString(check.host);
	auto address = QHostAddress();
	auto normalizedHost = host.toLower();
	if (address.setAddress(host)) {
		normalizedHost = address.toString().toLower();
	}
	if (check.ipv6) {
		normalizedHost = u"["_q + normalizedHost + u"]"_q;
	}
	return normalizedHost + u":"_q + QString::number(check.port);
}

[[nodiscard]] QByteArray ChecksumForPayload(const QString &payload) {
	const auto utf8 = payload.toUtf8();
	const auto digest = openssl::Sha256(bytes::make_span(utf8));
	return QByteArray(
		reinterpret_cast<const char *>(digest.data()),
		int(digest.size())).toHex();
}

[[nodiscard]] bool IsLowerHex(const QString &value) {
	for (const auto ch : value) {
		const auto code = ch.unicode();
		if (!((code >= '0' && code <= '9')
			|| (code >= 'a' && code <= 'f'))) {
			return false;
		}
	}
	return true;
}

} // namespace

ServerEnrollmentStatus ServerEnrollmentStatusFromKeyStatus(
		ServerKeyStatus status) {
	return KeyFailureStatus(status);
}

const char *ServerEnrollmentStatusName(ServerEnrollmentStatus status) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch-enum"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(4:4062)
#pragma warning(error:4062)
#endif // __GNUC__ || __clang__ || _MSC_VER
	switch (status) {
	case ServerEnrollmentStatus::Valid: return "Valid";
	case ServerEnrollmentStatus::MissingEndpoint: return "MissingEndpoint";
	case ServerEnrollmentStatus::MissingKey: return "MissingKey";
	case ServerEnrollmentStatus::MultipleEndpoints: return "MultipleEndpoints";
	case ServerEnrollmentStatus::MultipleKeys: return "MultipleKeys";
	case ServerEnrollmentStatus::TruncatedEnvelope: return "TruncatedEnvelope";
	case ServerEnrollmentStatus::UnparseableEnvelope: return "UnparseableEnvelope";
	case ServerEnrollmentStatus::TrailingContent: return "TrailingContent";
	case ServerEnrollmentStatus::EndpointNoPort: return "EndpointNoPort";
	case ServerEnrollmentStatus::EndpointBadPort: return "EndpointBadPort";
	case ServerEnrollmentStatus::EndpointEmptyHost:
		return "EndpointEmptyHost";
	case ServerEnrollmentStatus::EndpointBadHost: return "EndpointBadHost";
	case ServerEnrollmentStatus::EndpointHostTooLong:
		return "EndpointHostTooLong";
	case ServerEnrollmentStatus::EndpointUnbracketedIPv6:
		return "EndpointUnbracketedIPv6";
	case ServerEnrollmentStatus::UnreadableKey: return "UnreadableKey";
	case ServerEnrollmentStatus::PrivateKey: return "PrivateKey";
	case ServerEnrollmentStatus::NotRsaKey: return "NotRsaKey";
	case ServerEnrollmentStatus::BadModulusSize: return "BadModulusSize";
	case ServerEnrollmentStatus::InternalKeyError:
		return "InternalKeyError";
	}
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif // __GNUC__ || __clang__ || _MSC_VER
	return nullptr;
}

ServerEnrollmentCheck CheckServerEnrollment(const QString &artifact) {
	const auto normalized = NormalizeLineEndings(artifact);
	if (!normalized || normalized->isEmpty()) {
		return Failure(ServerEnrollmentStatus::UnparseableEnvelope);
	}

	const auto lines = normalized->split(QChar::fromLatin1('\n'));
	if (lines.front() != QString::fromLatin1(kHeader)) {
		return Failure(ServerEnrollmentStatus::UnparseableEnvelope);
	}

	const auto footerIndex = lines.indexOf(QString::fromLatin1(kFooter));
	if (footerIndex < 0) {
		return Failure(ServerEnrollmentStatus::TruncatedEnvelope);
	} else if (footerIndex != lines.size() - 1) {
		return Failure(ServerEnrollmentStatus::TrailingContent);
	}

	auto endpointCount = 0;
	auto keyBeginCount = 0;
	auto keyEndCount = 0;
	auto pemKeyCount = 0;
	auto checksumCount = 0;
	auto privateKeyPresent = false;
	for (auto i = 1; i != footerIndex; ++i) {
		const auto &line = lines[i];
		if (line.startsWith(QString::fromLatin1(kEndpointPrefix))) {
			++endpointCount;
		}
		if (line == QString::fromLatin1(kKeyBegin)) {
			++keyBeginCount;
		}
		if (line == QString::fromLatin1(kKeyEnd)) {
			++keyEndCount;
		}
		if (IsPemKeyBegin(line)) {
			++pemKeyCount;
			privateKeyPresent = privateKeyPresent
				|| IsPemPrivateKeyBegin(line);
		}
		if (line.startsWith(u"checksum="_q)) {
			++checksumCount;
		}
	}

	if (endpointCount > 1) {
		return Failure(ServerEnrollmentStatus::MultipleEndpoints);
	}
	if (privateKeyPresent) {
		return Failure(ServerEnrollmentStatus::PrivateKey);
	}
	if (keyBeginCount > 1 || keyEndCount > 1 || pemKeyCount > 1) {
		return Failure(ServerEnrollmentStatus::MultipleKeys);
	}
	if (!endpointCount) {
		return Failure(ServerEnrollmentStatus::MissingEndpoint);
	}
	if (!keyBeginCount) {
		return Failure(ServerEnrollmentStatus::MissingKey);
	}
	if (!checksumCount) {
		return Failure(ServerEnrollmentStatus::TruncatedEnvelope);
	}
	if (checksumCount > 1) {
		return Failure(ServerEnrollmentStatus::UnparseableEnvelope);
	}

	const auto endpointLine = lines[1];
	if (lines.size() <= 2
		|| !endpointLine.startsWith(QString::fromLatin1(kEndpointPrefix))
		|| lines[2] != QString::fromLatin1(kKeyBegin)) {
		return Failure(ServerEnrollmentStatus::UnparseableEnvelope);
	}

	const auto keyEndIndex = lines.indexOf(
		QString::fromLatin1(kKeyEnd),
		3);
	const auto checksumIndex = [&] {
		for (auto i = 3; i != footerIndex; ++i) {
			if (lines[i].startsWith(u"checksum="_q)) {
				return i;
			}
		}
		return -1;
	}();
	if (keyEndIndex < 0) {
		return Failure(ServerEnrollmentStatus::TruncatedEnvelope);
	}
	if (checksumIndex < 0
		|| keyEndIndex + 1 != checksumIndex
		|| checksumIndex + 1 != footerIndex) {
		return Failure(ServerEnrollmentStatus::UnparseableEnvelope);
	}
	if (pemKeyCount == 1
		&& (!IsPemKeyBegin(lines[3])
			|| !IsPemKeyEnd(lines[keyEndIndex - 1]))) {
		return Failure(ServerEnrollmentStatus::UnreadableKey);
	}

	const auto endpointCheck = CheckServerEndpoint(
		endpointLine.mid(QString::fromLatin1(kEndpointPrefix).size()));
	if (!endpointCheck) {
		return Failure(EndpointFailureStatus(endpointCheck.status));
	}

	const auto keyText = lines.mid(
		3,
		keyEndIndex - 3).join(QChar::fromLatin1('\n'));
	const auto keyCheck = CheckServerKey(keyText);
	if (!keyCheck) {
		return Failure(
			ServerEnrollmentStatusFromKeyStatus(keyCheck.status),
			keyCheck.modulusBits);
	}

	const auto endpoint = NormalizeEndpoint(endpointCheck);
	const auto payload = QString::fromLatin1(kHeader)
		+ u"\nendpoint="_q
		+ endpoint
		+ u"\npublic-key-begin\n"_q
		+ keyText
		+ u"\npublic-key-end\n"_q;
	const auto expectedChecksum = ChecksumForPayload(payload);
	const auto checksumLine = lines[checksumIndex];
	const auto checksum = checksumLine.mid(
		QString::fromLatin1(kChecksumPrefix).size());
	if (!checksumLine.startsWith(QString::fromLatin1(kChecksumPrefix))
		|| checksum.size() != expectedChecksum.size()
		|| !IsLowerHex(checksum)
		|| checksum.toLatin1() != expectedChecksum) {
		return Failure(ServerEnrollmentStatus::UnparseableEnvelope);
	}

	return {
		.status = ServerEnrollmentStatus::Valid,
		.endpoint = endpoint.toStdString(),
		.key = std::move(keyCheck.key),
		.identity = std::move(keyCheck.identity),
	};
}

bool CommitServerEnrollment(
		const std::function<bool()> &setPin,
		const std::function<bool()> &persistPin,
		const std::function<void()> &resume,
		const std::function<void()> &rollbackPin) {
	if (!setPin()) {
		return false;
	}
	if (!persistPin()) {
		if (rollbackPin) {
			rollbackPin();
		}
		return false;
	}
	resume();
	return true;
}

bool IsServerEnrollmentActivationKey(int key) {
	return key == Qt::Key_Enter
		|| key == Qt::Key_Return
		|| key == Qt::Key_Space;
}

bool ConsumeServerEnrollmentActivationKey(QKeyEvent &event) {
	if (!IsServerEnrollmentActivationKey(event.key())) {
		return false;
	}
	event.accept();
	return true;
}

} // namespace MTP
