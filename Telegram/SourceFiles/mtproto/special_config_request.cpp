/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/special_config_request.h"

namespace MTP::details {

SpecialConfigRequest::SpecialConfigRequest(
	Fn<void(
		DcId,
		const std::string &,
		int,
		bytes::const_span)>,
	bool,
	const QString &,
	const QString &) {
}

SpecialConfigRequest::SpecialConfigRequest(
	Fn<void()>,
	bool,
	const QString &) {
}

} // namespace MTP::details
