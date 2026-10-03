/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "platform/platform_file_utilities.h"

#include "core/mac_protected_path_access.h"
#include "test/test_launch_fuse.h"

namespace Platform::File {

void UnsafeOpenUrl(const QString &url) {
	const auto localPath = Core::MacProtectedPath::LocalFilePathFromUrl(url);
	if (localPath) {
		(void)Core::MacProtectedPath::DispatchExternalPathIfAllowed(
			Core::MacProtectedPath::Operation::Open, *localPath,
			"platform.open-url", [&] {
				if (!Test::BlockLaunch(u"UnsafeOpenUrl"_q, url)) {
					Unfused::UnsafeOpenUrl(url);
				}
			});
		return;
	}
	if (!Test::BlockLaunch(u"UnsafeOpenUrl"_q, url)) {
		Unfused::UnsafeOpenUrl(url);
	}
}

void UnsafeOpenEmailLink(const QString &email) {
	if (Test::BlockLaunch(u"UnsafeOpenEmailLink"_q, email)) {
		return;
	}
	Unfused::UnsafeOpenEmailLink(email);
}

bool UnsafeShowOpenWithDropdown(const QString &filepath) {
	auto result = false;
	const auto dispatched
		= Core::MacProtectedPath::DispatchExternalPathIfAllowed(
			Core::MacProtectedPath::Operation::Open, filepath,
			"platform.open-with-dropdown", [&] {
				result = Test::BlockLaunch(u"UnsafeShowOpenWithDropdown"_q,
										   filepath)
						 || Unfused::UnsafeShowOpenWithDropdown(filepath);
			});
	return !dispatched || result;
}

bool UnsafeShowOpenWith(const QString &filepath) {
	auto result = false;
	const auto dispatched
		= Core::MacProtectedPath::DispatchExternalPathIfAllowed(
			Core::MacProtectedPath::Operation::Open, filepath,
			"platform.open-with", [&] {
				result = Test::BlockLaunch(u"UnsafeShowOpenWith"_q, filepath)
						 || Unfused::UnsafeShowOpenWith(filepath);
			});
	return !dispatched || result;
}

void UnsafeLaunch(const QString &filepath) {
	(void)Core::MacProtectedPath::DispatchExternalPathIfAllowed(
		Core::MacProtectedPath::Operation::Open, filepath, "platform.launch",
		[&] {
			if (!Test::BlockLaunch(u"UnsafeLaunch"_q, filepath)) {
				Unfused::UnsafeLaunch(filepath);
			}
		});
}

} // namespace Platform::File
