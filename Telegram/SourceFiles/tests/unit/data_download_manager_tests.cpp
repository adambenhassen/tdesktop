/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "core/mac_protected_path_access.h"
#include "data/data_download_manager.h"

#include <vector>

namespace {

using namespace Core::MacProtectedPath;

} // namespace

TEST_CASE(RefusedHistoryEntryWithoutLiveMessageRemainsUnpublished) {
	const auto protectedPath = u"/Users/alice/Library/Application Support/"_q
							   + u"Telegram Desktop/tdata/download"_q;
	auto downloaded = std::vector<Data::DownloadedId>();
	downloaded.push_back(Data::DownloadedId{
		.path = protectedPath,
	});
	auto &entry = downloaded.front();
	const auto liveMessageFound = false;
	auto refused = false;
	auto published = false;
	if (!liveMessageFound) {
		Data::details::GenerateAndNotifyLoadedEntry(
			entry,
			[&](Data::DownloadedId &candidate) {
				refused = !PersistedExternalPath(candidate.path)
							   .allowed(Operation::Read,
										"download-history.generate",
										[](Operation, const QString &,
										   const char *) { return false; });
			},
			[&](const Data::DownloadedId *) { published = true; });
	}
	CHECK(refused);
	CHECK(!published);
	CHECK(downloaded.size() == 1);
	CHECK_EQ(entry.path, protectedPath);
	CHECK(!entry.object);
}
