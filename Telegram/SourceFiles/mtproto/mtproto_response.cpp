/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/mtproto_response.h"
#include "mtproto/mtp_instance.h"

#include <QtCore/QRegularExpression>
#include <QtCore/QDebug>
#include <QtCore/QObject>

namespace MTP {
namespace {

[[nodiscard]] MTPrpcError ParseError(const mtpBuffer &reply) {
	auto result = MTPRpcError();
	auto from = reply.constData();
	return result.read(from, from + reply.size())
		? result
		: Error::MTPLocal("RESPONSE_PARSE_FAILED", "Error parse failed.");
}

} // namespace

Error::Error(const MTPrpcError &error)
: _code(error.c_rpc_error().verror_code().v) {
	QString text = qs(error.c_rpc_error().verror_message());
	static const auto Expression = QRegularExpression(
		"^([A-Z0-9_]+)(: .*)?$",
		(QRegularExpression::DotMatchesEverythingOption
			| QRegularExpression::MultilineOption));
	const auto match = Expression.match(text);
	if (match.hasMatch()) {
		_type = match.captured(1);
		_description = match.captured(2).mid(2);
	} else if (_code < 0 || _code >= 500) {
		_type = "INTERNAL_SERVER_ERROR";
		_description = text;
	} else {
		_type = "CLIENT_BAD_RPC_ERROR";
		_description = "Bad rpc error received, text = '" + text + '\'';
	}
}

Error::Error(const mtpBuffer &reply) : Error(ParseError(reply)) {
}

int32 Error::code() const {
	return _code;
}

const QString &Error::type() const {
	return _type;
}

const QString &Error::description() const {
	return _description;
}

MTPrpcError Error::MTPLocal(
		const QString &type,
		const QString &description) {
	return MTP_rpc_error(
		MTP_int(0),
		MTP_bytes(
			("CLIENT_"
				+ type
				+ (description.length()
					? (": " + description)
					: QString())).toUtf8()));
}

Error Error::Local(
		const QString &type,
		const QString &description) {
	return Error(MTPLocal(type, description));
}

bool RejectServerEnrollmentRequest(
		bool networkAllowed,
		mtpRequestId requestId,
		ResponseHandler &callbacks,
		not_null<QObject*> context) {
	if (networkAllowed) {
		return false;
	}
	if (callbacks.fail) {
		QMetaObject::invokeMethod(context.get(), [
			requestId,
			fail = std::move(callbacks.fail)
		]() mutable {
			fail(
				Error::Local(
					u"SERVER_ENROLLMENT_PAUSED"_q,
					u"Network access is paused until server enrollment completes."_q),
				Response{ .requestId = requestId });
		}, Qt::QueuedConnection);
	}
	return true;
}

QDebug operator<<(QDebug debug, const Error &error) {
	return debug.nospace()
		<< "MTP::Error("
		<< error.code()
		<< ", "
		<< error.type()
		<< ", "
		<< error.description()
		<< ")";
}

} // namespace MTP
