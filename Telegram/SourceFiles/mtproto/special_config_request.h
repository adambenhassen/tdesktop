/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/bytes.h"
#include "base/weak_ptr.h"
#include "mtproto/mtproto_dc_options.h"

namespace MTP::details {

// The historical implementation queried Telegram-owned DNS and Firebase
// services to discover production DCs. Server enrollment is explicit now, so
// this type remains only as a source-compatible no-op for old call sites. It
// never creates a network request or invokes either callback.
class SpecialConfigRequest {
public:
	SpecialConfigRequest(
		Fn<void(
			DcId dcId,
			const std::string &ip,
			int port,
			bytes::const_span secret)> callback,
		bool isTestMode,
		const QString &domainString,
		const QString &phone);
	SpecialConfigRequest(
		Fn<void()> timeDoneCallback,
		bool isTestMode,
		const QString &domainString);
};

} // namespace MTP::details
