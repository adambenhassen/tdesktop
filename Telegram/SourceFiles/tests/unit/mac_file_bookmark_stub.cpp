/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "platform/mac/file_bookmark_mac.h"

namespace Platform {

FileBookmark::FileBookmark(const QByteArray &) {}

FileBookmark::~FileBookmark() = default;

bool FileBookmark::check() const { return true; }

bool FileBookmark::rejected() const { return _rejected; }

bool FileBookmark::enable() const { return true; }

void FileBookmark::disable() const {}

const QString &FileBookmark::name(const QString &original) const {
	return original;
}

QByteArray FileBookmark::bookmark() const { return QByteArray(); }

QByteArray PathBookmark(const QString &) { return QByteArray(); }

} // namespace Platform
