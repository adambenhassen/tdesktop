/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

namespace MTP::details {

enum class PersistentKeyErrorTransport {
	Tcp,
	Http,
};

struct PersistentKeyErrorContext {
	PersistentKeyErrorTransport transport = PersistentKeyErrorTransport::Tcp;
	bool pinnedEndpoint = false;
	uint64 connectionGeneration = 0;
	uint64 currentGeneration = 0;
	uint64 presentedKeyId = 0;
	uint64 persistentKeyId = 0;
};

[[nodiscard]] inline bool ShouldDiscardPersistentKeyOn404(
	const PersistentKeyErrorContext &context) {
	return (context.transport == PersistentKeyErrorTransport::Tcp)
		&& context.pinnedEndpoint
		&& (context.connectionGeneration == context.currentGeneration)
		&& (context.persistentKeyId != 0)
		&& (context.presentedKeyId == context.persistentKeyId);
}

} // namespace MTP::details
