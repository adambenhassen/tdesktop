/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "storage/storage_server_forget_startup.h"

namespace Storage::details {

ServerForgetStartupResult ProcessServerForgetStartup(
		bool serverForgetPending,
		Fn<void(bool)> readMapWith,
		Fn<void()> clearLegacyFiles,
		Fn<bool()> completeServerForget,
		Fn<void()> readStoredCustomServerPin,
		Fn<void()> readMtpConfig) {
	readMapWith(serverForgetPending);
	clearLegacyFiles();
	if (serverForgetPending) {
		return completeServerForget()
			? ServerForgetStartupResult::Forgotten
			: ServerForgetStartupResult::Blocked;
	}
	readStoredCustomServerPin();
	readMtpConfig();
	return ServerForgetStartupResult::Loaded;
}

} // namespace Storage::details
