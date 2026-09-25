/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "mtproto/persistent_key_rejection.h"

namespace {

using namespace MTP::details;

PersistentKeyErrorContext CurrentTcpRejection() {
	return {
		.transport = PersistentKeyErrorTransport::Tcp,
		.pinnedEndpoint = true,
		.connectionGeneration = 7,
		.currentGeneration = 7,
		.presentedKeyId = 0x1234,
		.persistentKeyId = 0x1234,
	};
}

} // namespace

TEST_CASE(Http404KeepsPersistentKey) {
	auto context = CurrentTcpRejection();
	context.transport = PersistentKeyErrorTransport::Http;
	CHECK(!ShouldDiscardPersistentKeyOn404(context));
}

TEST_CASE(StaleConnection404KeepsPersistentKey) {
	auto context = CurrentTcpRejection();
	context.connectionGeneration = 6;
	CHECK(!ShouldDiscardPersistentKeyOn404(context));
}

TEST_CASE(WrongKeyId404KeepsPersistentKey) {
	auto context = CurrentTcpRejection();
	context.presentedKeyId = 0x5678;
	CHECK(!ShouldDiscardPersistentKeyOn404(context));
}

TEST_CASE(UnpinnedEndpoint404KeepsPersistentKey) {
	auto context = CurrentTcpRejection();
	context.pinnedEndpoint = false;
	CHECK(!ShouldDiscardPersistentKeyOn404(context));
}

TEST_CASE(CurrentPinnedTcp404DiscardsPersistentKey) {
	CHECK(ShouldDiscardPersistentKeyOn404(CurrentTcpRejection()));
}
