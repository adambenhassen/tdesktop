/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/file_location.h"

#include "core/mac_protected_path_access.h"
#include "core/mac_protected_path_runtime.h"
#include "platform/platform_file_bookmark.h"
#include "logs.h"

#include <QtCore/QFileInfo>

namespace Core {
using MacProtectedPath::Operation;

namespace {

const auto kInMediaCacheLocation = u"*media_cache*"_q;
constexpr auto kMaxFileSize = 4000 * int64(1024 * 1024);

} // namespace

ReadAccessEnabler::ReadAccessEnabler(const Platform::FileBookmark *bookmark)
: _bookmark(bookmark)
, _failed(_bookmark ? !_bookmark->enable() : false) {
}

ReadAccessEnabler::ReadAccessEnabler(
	const std::shared_ptr<Platform::FileBookmark> &bookmark)
: _bookmark(bookmark.get())
, _failed(_bookmark ? !_bookmark->enable() : false) {
}

ReadAccessEnabler::~ReadAccessEnabler() {
	if (_bookmark && !_failed) _bookmark->disable();
}

FileLocation::FileLocation(const QString &name) : fname(name) {
	if (fname.isEmpty() || fname == kInMediaCacheLocation) {
		size = 0;
	} else if (!MacProtectedPath::PersistedExternalPath(fname).allowed(
				   Operation::Read, "file-location.construct")) {
		size = 0;
	} else {
		setBookmark(Platform::PathBookmark(name));
		resolveFromInfo(QFileInfo(name));
	}
}

FileLocation::FileLocation(const QFileInfo &info) : fname(info.filePath()) {
	if (fname.isEmpty()) {
		size = 0;
	} else if (!MacProtectedPath::PersistedExternalPath(fname).allowed(
				   Operation::Read, "file-location.construct-info")) {
		size = 0;
	} else {
		setBookmark(Platform::PathBookmark(fname));
		resolveFromInfo(info);
	}
}

void FileLocation::resolveFromInfo(const QFileInfo &info) {
	if (!MacProtectedPath::PersistedExternalPath(info.filePath())
			 .allowed(Operation::Read, "file-location.resolve-info")) {
		return;
	}
	if (info.exists()) {
		const auto s = info.size();
		if (s > kMaxFileSize) {
			fname = QString();
			_bookmark = nullptr;
			size = 0;
		} else {
			modified = info.lastModified();
			size = s;
		}
	} else {
		fname = QString();
		_bookmark = nullptr;
		size = 0;
	}
}

FileLocation FileLocation::InMediaCacheLocation() {
	return FileLocation(kInMediaCacheLocation);
}

bool FileLocation::check() const {
	if (fname.isEmpty() || fname == kInMediaCacheLocation) {
		return false;
	}
	const auto &checkedName = name();
	if (checkedName.isEmpty()) {
		return false;
	}

	ReadAccessEnabler enabler(_bookmark);
	if (enabler.failed()) {
		const_cast<FileLocation*>(this)->_bookmark = nullptr;
	}

	QFileInfo f(checkedName);
	if (!f.isReadable()) return false;

	quint64 s = f.size();
	if (s > kMaxFileSize) {
		DEBUG_LOG(("File location check: Wrong size %1").arg(s));
		return false;
	}

	if (s != size) {
		DEBUG_LOG(("File location check: Wrong size %1 when should be %2").arg(s).arg(size));
		return false;
	}
	auto realModified = f.lastModified();
	if (realModified != modified) {
		DEBUG_LOG(("File location check: Wrong last modified time %1 when should be %2").arg(realModified.toMSecsSinceEpoch()).arg(modified.toMSecsSinceEpoch()));
		return false;
	}
	return true;
}

bool FileLocation::pathRefused() const {
	return !fname.isEmpty() && fname != kInMediaCacheLocation
		   && ((_bookmark && _bookmark->rejected()) || name().isEmpty());
}

const QString &FileLocation::name() const {
	static const auto Empty = QString();
	if (fname.isEmpty() || fname == kInMediaCacheLocation
		|| !MacProtectedPath::PersistedExternalPath(fname).allowed(
			Operation::Read, "file-location.name")
		|| (_bookmark && _bookmark->rejected())) {
		return Empty;
	}
	const auto &result = _bookmark ? _bookmark->name(fname) : fname;
	return MacProtectedPath::PersistedExternalPath(result)
				   .forUse(Operation::Read, "file-location.bookmark-name")
				   .isEmpty()
			   ? Empty
			   : result;
}

QString FileLocation::serializedName() const {
	if (fname.isEmpty() || fname == kInMediaCacheLocation) {
		return fname;
	}
	if (!MacProtectedPath::PersistedExternalPath(fname).allowed(
			Operation::Read, "file-location.serialize")
		|| (_bookmark && _bookmark->rejected())) {
		return fname;
	}
	const auto &result = _bookmark ? _bookmark->name(fname) : fname;
	return MacProtectedPath::PersistedExternalPath(result).allowed(
			   Operation::Read, "file-location.serialize-bookmark")
			   ? result
			   : fname;
}

QByteArray FileLocation::bookmark() const {
	return (_bookmark && !_bookmark->rejected()) ? _bookmark->bookmark()
												 : _serializedBookmark;
}

bool FileLocation::inMediaCache() const {
	return (fname == kInMediaCacheLocation);
}

void FileLocation::setBookmark(const QByteArray &bm) {
	_serializedBookmark = bm;
	_bookmark.reset();
	if (!bm.isEmpty() && !fname.isEmpty() && fname != kInMediaCacheLocation
		&& MacProtectedPath::PersistedExternalPath(fname).allowed(
			Operation::Read, "file-location.bookmark-load")) {
		_bookmark = std::make_shared<Platform::FileBookmark>(bm);
	}
}

bool FileLocation::accessEnable() const {
	return !name().isEmpty() && (_bookmark ? _bookmark->enable() : true);
}

void FileLocation::accessDisable() const {
	return _bookmark ? _bookmark->disable() : (void)0;
}

} // namespace Core
