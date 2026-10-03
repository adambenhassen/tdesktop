/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/flat_map.h"
#include "core/mac_protected_path_access.h"

#include <rpl/variable.h>

#include <QtCore/QDataStream>

#include <utility>

namespace Core {

// Settings keeps these paths even when the current process is not allowed to
// use them, so a refused value can be reconsidered after a future restart.
class SettingsExternalPaths final {
  public:
	[[nodiscard]] const QString &downloadPathStored() const {
		return _downloadPath.current();
	}
	[[nodiscard]] rpl::producer<QString> downloadPathValue() const {
		return _downloadPath.value();
	}
	[[nodiscard]] QString downloadPath() const {
		const auto &path = _downloadPath.current();
		if (path.isEmpty() || path == TmpDownloadPath()) {
			return path;
		}
		return MacProtectedPath::PersistedExternalPath(path).forUse(
			MacProtectedPath::Operation::OpenDir, "settings.download-path");
	}
	void setDownloadPath(const QString &path) {
		if (path == TmpDownloadPath()
			|| MacProtectedPath::PersistedExternalPath(path).allowed(
				MacProtectedPath::Operation::OpenDir,
				"settings.download-path.set")) {
			_downloadPath = path;
		}
	}
	void setDownloadPathFromSerialized(const QString &path) {
		if (path != TmpDownloadPath()) {
			(void)MacProtectedPath::PersistedExternalPath(path).allowed(
				MacProtectedPath::Operation::OpenDir,
				"settings.download-path.load");
		}
		_downloadPath = path;
	}
	void serializeDownloadPath(QDataStream &stream) const {
		stream << _downloadPath.current();
	}
	[[nodiscard]] static QString ReadDownloadPath(QDataStream &stream) {
		auto result = QString();
		stream >> result;
		return result;
	}
	[[nodiscard]] const base::flat_map<QString, QString> &
	soundOverrides() const {
		return _soundOverrides;
	}
	[[nodiscard]] QString getSoundPath(const QString &key) const {
		const auto i = _soundOverrides.find(key);
		if (i != _soundOverrides.end()
			&& MacProtectedPath::PersistedExternalPath(i->second).allowed(
				MacProtectedPath::Operation::Read, "settings.sound-override")) {
			return i->second;
		}
		return u":/sounds/"_q + key + u".mp3"_q;
	}
	void setSoundOverride(const QString &key, const QString &path) {
		if (MacProtectedPath::PersistedExternalPath(path).allowed(
				MacProtectedPath::Operation::Read,
				"settings.sound-override.set")) {
			_soundOverrides.emplace(key, path);
		}
	}
	void setSoundOverrideFromSerialized(const QString &key,
										const QString &path) {
		(void)MacProtectedPath::PersistedExternalPath(path).allowed(
			MacProtectedPath::Operation::Read,
			"settings.sound-override.legacy-load");
		_soundOverrides.emplace(key, path);
	}
	void restoreSoundOverridesFromSerialized(
		base::flat_map<QString, QString> soundOverrides) {
		_soundOverrides.clear();
		for (const auto &[key, path] : soundOverrides) {
			(void)MacProtectedPath::PersistedExternalPath(path).allowed(
				MacProtectedPath::Operation::Read,
				"settings.sound-override.load");
			_soundOverrides.emplace(key, path);
		}
	}
	void serializeSoundOverrides(QDataStream &stream) const {
		stream << qint32(_soundOverrides.size());
		for (const auto &[key, value] : _soundOverrides) {
			stream << key << value;
		}
	}
	[[nodiscard]] static base::flat_map<QString, QString>
	ReadSoundOverrides(QDataStream &stream, qint32 count) {
		auto result = base::flat_map<QString, QString>();
		for (auto i = 0; i != count; ++i) {
			auto key = QString();
			auto path = QString();
			stream >> key >> path;
			result.emplace(std::move(key), std::move(path));
		}
		return result;
	}
	void clearSoundOverrides() { _soundOverrides.clear(); }
	void reset() {
		_downloadPath = QString();
		_soundOverrides.clear();
	}

  private:
	[[nodiscard]] static const QString &TmpDownloadPath() {
		static const auto result = u"tmp"_q;
		return result;
	}

	rpl::variable<QString> _downloadPath;
	base::flat_map<QString, QString> _soundOverrides;
};

} // namespace Core
