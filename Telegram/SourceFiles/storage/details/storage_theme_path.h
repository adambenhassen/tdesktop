/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "core/mac_protected_path_access.h"
#include "window/themes/window_theme.h"

#include <QtCore/QDir>
#include <QtCore/QFile>

namespace Storage::details {

struct ThemePathLoadResult {
	bool refusedPath = false;
	bool contentChanged = false;
	QString tooLargePath;
	qint64 tooLargeSize = 0;
};

[[nodiscard]] inline ThemePathLoadResult
LoadThemeFileContent(Window::Theme::Object &object) {
	using Core::MacProtectedPath::Operation;
	const auto check = [](Operation operation, const QString &path,
						  const char *callsite) {
		return path.startsWith(u":/"_q) || path.startsWith(u"qrc:/"_q)
			   || Core::MacProtectedPath::PersistedExternalPath(path).allowed(
				   operation, callsite);
	};

	const auto relativePath
		= object.pathRelative.isEmpty()
				  || object.pathRelative.startsWith(u":/"_q)
				  || object.pathRelative.startsWith(u"qrc:/"_q)
			  ? object.pathRelative
			  : QDir().absoluteFilePath(object.pathRelative);
	const auto relativeAllowed = object.pathRelative.isEmpty()
								 || check(Operation::Read, relativePath,
										  "theme.persisted-relative-path");
	const auto absoluteAllowed = object.pathAbsolute.isEmpty()
								 || check(Operation::Read, object.pathAbsolute,
										  "theme.persisted-absolute-path");
	auto result = ThemePathLoadResult();
	result.refusedPath = !relativeAllowed || !absoluteAllowed;
	if (result.refusedPath) {
		return result;
	}

	auto file = QFile(relativePath);
	if (object.pathRelative.isEmpty()) {
		file.setFileName(object.pathAbsolute);
	} else if (check(Operation::Stat, file.fileName(),
					 "theme.persisted-relative-stat")
			   && !file.exists()) {
		file.setFileName(object.pathAbsolute);
	}
	if (!file.fileName().isEmpty()
		&& check(Operation::Stat, file.fileName(), "theme.persisted-stat")
		&& file.exists()
		&& Core::MacProtectedPath::OpenExternalFile(
			file, QIODevice::ReadOnly, Operation::Read, "theme.persisted-read",
			check)) {
		constexpr auto kThemeFileSizeLimit = 5 * 1024 * 1024;
		if (file.size() > kThemeFileSizeLimit) {
			result.tooLargePath = file.fileName();
			result.tooLargeSize = file.size();
			return result;
		}
		const auto fileContent = file.readAll();
		file.close();
		if (object.content != fileContent) {
			object.content = fileContent;
			result.contentChanged = true;
		}
	}
	return result;
}

} // namespace Storage::details
