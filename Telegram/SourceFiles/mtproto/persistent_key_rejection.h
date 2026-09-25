/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/mtproto_dc_options.h"

#include <QtCore/QString>

namespace MTP::details {

struct ConnectionErrorInfo {
	uint64 generation = 0;
	QString endpoint;
	int port = 0;
	DcOptions::Variants::Protocol protocol = DcOptions::Variants::Tcp;
	CustomServer pin;
	uint64 presentedKeyId = 0;
	bool proxied = false;
	QString proxyEndpoint;
	int proxyPort = 0;
};

enum class PersistentKeyErrorDecision {
	KeepAndRetry,
	KeepAndStop,
	Discard,
};

[[nodiscard]] inline PersistentKeyErrorDecision DecidePersistentKey404(
		const ConnectionErrorInfo &connection,
		const CustomServer &currentPin,
		uint64 currentGeneration,
		uint64 encryptionKeyId,
		uint64 persistentKeyId) {
	if (connection.proxied) {
		return PersistentKeyErrorDecision::KeepAndStop;
	}
	const auto samePin = connection.pin.key
		&& currentPin.key
		&& SameCustomServerPin(connection.pin, currentPin);
	const auto sameKey = (persistentKeyId != 0)
		&& (encryptionKeyId == persistentKeyId)
		&& (connection.presentedKeyId == persistentKeyId);
	return (connection.protocol == DcOptions::Variants::Tcp)
		&& samePin
		&& (connection.generation == currentGeneration)
		&& sameKey
		? PersistentKeyErrorDecision::Discard
		: PersistentKeyErrorDecision::KeepAndRetry;
}

} // namespace MTP::details
