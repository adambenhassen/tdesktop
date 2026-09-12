/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "storage/storage_account.h"

#include "base/const_string.h"
#include "mtproto/mtproto_config.h"
#include "storage/details/storage_file_utilities.h"
#include "storage/serialize_common.h"
#include "storage/serialize_peer.h"

#include <QtCore/QDir>

namespace Storage {
namespace {

using namespace details;

constexpr auto kDelayedWriteTimeout = crl::time(1000);

enum { // Local Storage Keys
	lskUserMap = 0x00,
	lskDraft = 0x01,
	lskDraftPosition = 0x02,
	lskLegacyImages = 0x03,
	lskLocations = 0x04,
	lskLegacyStickerImages = 0x05,
	lskLegacyAudios = 0x06,
	lskRecentStickersOld = 0x07,
	lskBackgroundOldOld = 0x08,
	lskUserSettings = 0x09,
	lskRecentHashtagsAndBots = 0x0a,
	lskStickersOld = 0x0b,
	lskSavedPeersOld = 0x0c,
	lskReportSpamStatusesOld = 0x0d,
	lskSavedGifsOld = 0x0e,
	lskSavedGifs = 0x0f,
	lskStickersKeys = 0x10,
	lskTrustedPeers = 0x11,
	lskFavedStickers = 0x12,
	lskExportSettings = 0x13,
	lskBackgroundOld = 0x14,
	lskSelfSerialized = 0x15,
	lskMasksKeys = 0x16,
	lskCustomEmojiKeys = 0x17,
	lskSearchSuggestions = 0x18,
	lskWebviewTokens = 0x19,
	lskRoundPlaceholder = 0x1a,
	lskInlineBotsDownloads = 0x1b,
	lskMediaLastPlaybackPositions = 0x1c,
	lskBotStorages = 0x1d,
	lskPrefs = 0x1e,
};

constexpr auto kCustomServerPinnedPref = "mtp_custom_server_pinned"_cs;
constexpr auto kCustomServerPinUnknownPref = "mtp_custom_server_unknown"_cs;

} // namespace

#ifdef TDESKTOP_UNIT_TESTS

Account::Account(
		const QString &basePath,
		MTP::AuthKeyPtr localKey,
		std::shared_ptr<const MTP::Config> config,
		bool hasStoredCustomServer)
: _owner(nullptr)
, _basePath(basePath.endsWith(QDir::separator())
	? basePath
	: basePath + QDir::separator())
, _localKey(std::move(localKey))
, _hasStoredCustomServer(hasStoredCustomServer)
, _mtpConfig([config = std::move(config)]() -> const MTP::Config & {
	return *config;
})
, _serializeSelf(nullptr)
, _queueMapWrite(nullptr)
, _writeMapTimer([this] { writeMap(); })
, _writePrefsTimer([this] { writePrefs(); })
, _writeLocationsTimer(nullptr)
, _writeSearchSuggestionsTimer(nullptr) {
}

#endif // TDESKTOP_UNIT_TESTS

Account::~Account() {
	Expects(!_writeSearchSuggestionsTimer.isActive());

	if (_localKey) {
		if (_prefsChanged) {
			writePrefs();
		}
		if (_mapChanged) {
			writeMap();
		}
	}
}

void Account::writeMapDelayed() {
	_mapChanged = true;
	_writeMapTimer.callOnce(kDelayedWriteTimeout);
}

void Account::writeMapQueued() {
	_mapChanged = true;
	if (_queueMapWrite) {
		_queueMapWrite();
	} else {
		writeMap();
	}
}

bool Account::writeMap(bool sync) {
	Expects(_localKey != nullptr);

	_writeMapTimer.cancel();
	if (!_mapChanged) {
		return true;
	}

	if (!QDir().exists(_basePath)) {
		QDir().mkpath(_basePath);
	}

	FileWriteDescriptor map(u"map"_q, _basePath, sync);
	map.writeData(QByteArray());
	map.writeData(QByteArray());

	uint32 mapSize = 0;
	const auto self = _serializeSelf ? _serializeSelf() : QByteArray();
	if (!self.isEmpty()) mapSize += sizeof(quint32) + Serialize::bytearraySize(self);
	if (!_draftsMap.empty()) mapSize += sizeof(quint32) * 2 + _draftsMap.size() * sizeof(quint64) * 2;
	if (!_draftCursorsMap.empty()) mapSize += sizeof(quint32) * 2 + _draftCursorsMap.size() * sizeof(quint64) * 2;
	if (_prefsKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (_locationsKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (_trustedPeersKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (_recentStickersKeyOld) mapSize += sizeof(quint32) + sizeof(quint64);
	if (_installedStickersKey || _featuredStickersKey || _recentStickersKey || _archivedStickersKey) {
		mapSize += sizeof(quint32) + 4 * sizeof(quint64);
	}
	if (_favedStickersKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (_savedGifsKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (_settingsKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (_recentHashtagsAndBotsKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (_exportSettingsKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (_installedMasksKey || _recentMasksKey || _archivedMasksKey) {
		mapSize += sizeof(quint32) + 3 * sizeof(quint64);
	}
	if (_installedCustomEmojiKey || _featuredCustomEmojiKey || _archivedCustomEmojiKey) {
		mapSize += sizeof(quint32) + 3 * sizeof(quint64);
	}
	if (_searchSuggestionsKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (!_webviewStorageIdBots.token.isEmpty()
		|| !_webviewStorageIdOther.token.isEmpty()) {
		mapSize += sizeof(quint32)
			+ Serialize::bytearraySize(_webviewStorageIdBots.token)
			+ Serialize::bytearraySize(_webviewStorageIdOther.token);
	}
	if (_roundPlaceholderKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (_inlineBotsDownloadsKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (_mediaLastPlaybackPositionsKey) mapSize += sizeof(quint32) + sizeof(quint64);
	if (!_botStoragesMap.empty()) mapSize += sizeof(quint32) * 2 + _botStoragesMap.size() * sizeof(quint64) * 2;

	EncryptedDescriptor mapData(mapSize);
	if (!self.isEmpty()) {
		mapData.stream << quint32(lskSelfSerialized) << self;
	}
	if (!_draftsMap.empty()) {
		mapData.stream << quint32(lskDraft) << quint32(_draftsMap.size());
		for (const auto &[key, value] : _draftsMap) {
			mapData.stream << quint64(value) << SerializePeerId(key);
		}
	}
	if (!_draftCursorsMap.empty()) {
		mapData.stream << quint32(lskDraftPosition) << quint32(_draftCursorsMap.size());
		for (const auto &[key, value] : _draftCursorsMap) {
			mapData.stream << quint64(value) << SerializePeerId(key);
		}
	}
	if (_prefsKey) {
		mapData.stream << quint32(lskPrefs) << quint64(_prefsKey);
	}
	if (_locationsKey) {
		mapData.stream << quint32(lskLocations) << quint64(_locationsKey);
	}
	if (_trustedPeersKey) {
		mapData.stream << quint32(lskTrustedPeers) << quint64(_trustedPeersKey);
	}
	if (_recentStickersKeyOld) {
		mapData.stream << quint32(lskRecentStickersOld) << quint64(_recentStickersKeyOld);
	}
	if (_installedStickersKey || _featuredStickersKey || _recentStickersKey || _archivedStickersKey) {
		mapData.stream << quint32(lskStickersKeys);
		mapData.stream << quint64(_installedStickersKey) << quint64(_featuredStickersKey) << quint64(_recentStickersKey) << quint64(_archivedStickersKey);
	}
	if (_favedStickersKey) {
		mapData.stream << quint32(lskFavedStickers) << quint64(_favedStickersKey);
	}
	if (_savedGifsKey) {
		mapData.stream << quint32(lskSavedGifs) << quint64(_savedGifsKey);
	}
	if (_settingsKey) {
		mapData.stream << quint32(lskUserSettings) << quint64(_settingsKey);
	}
	if (_recentHashtagsAndBotsKey) {
		mapData.stream << quint32(lskRecentHashtagsAndBots) << quint64(_recentHashtagsAndBotsKey);
	}
	if (_exportSettingsKey) {
		mapData.stream << quint32(lskExportSettings) << quint64(_exportSettingsKey);
	}
	if (_installedMasksKey || _recentMasksKey || _archivedMasksKey) {
		mapData.stream << quint32(lskMasksKeys);
		mapData.stream
			<< quint64(_installedMasksKey)
			<< quint64(_recentMasksKey)
			<< quint64(_archivedMasksKey);
	}
	if (_installedCustomEmojiKey || _featuredCustomEmojiKey || _archivedCustomEmojiKey) {
		mapData.stream << quint32(lskCustomEmojiKeys);
		mapData.stream
			<< quint64(_installedCustomEmojiKey)
			<< quint64(_featuredCustomEmojiKey)
			<< quint64(_archivedCustomEmojiKey);
	}
	if (_searchSuggestionsKey) {
		mapData.stream << quint32(lskSearchSuggestions);
		mapData.stream << quint64(_searchSuggestionsKey);
	}
	if (!_webviewStorageIdBots.token.isEmpty()
		|| !_webviewStorageIdOther.token.isEmpty()) {
		mapData.stream << quint32(lskWebviewTokens);
		mapData.stream
			<< _webviewStorageIdBots.token
			<< _webviewStorageIdOther.token;
	}
	if (_roundPlaceholderKey) {
		mapData.stream << quint32(lskRoundPlaceholder);
		mapData.stream << quint64(_roundPlaceholderKey);
	}
	if (_inlineBotsDownloadsKey) {
		mapData.stream << quint32(lskInlineBotsDownloads);
		mapData.stream << quint64(_inlineBotsDownloadsKey);
	}
	if (_mediaLastPlaybackPositionsKey) {
		mapData.stream << quint32(lskMediaLastPlaybackPositions);
		mapData.stream << quint64(_mediaLastPlaybackPositionsKey);
	}
	if (!_botStoragesMap.empty()) {
		mapData.stream << quint32(lskBotStorages) << quint32(_botStoragesMap.size());
		for (const auto &[key, value] : _botStoragesMap) {
			mapData.stream << quint64(value) << SerializePeerId(key);
		}
	}
	map.writeEncrypted(mapData, _localKey);
	if (!map.finish()) {
		return false;
	}

	_mapChanged = false;
	return true;
}

bool Account::writeMtpConfig(bool sync) {
	Expects(_localKey != nullptr);

	Expects(_mtpConfig != nullptr);
	const auto &config = _mtpConfig();
	if (config.blocked()) {
		// This account is pinned to a custom server whose stored
		// settings could not be read back. Writing an empty config over
		// them would destroy the pinned key for good, and there is
		// nothing here worth keeping anyway.
		return false;
	}

	// The pin marker lives in its own tdata key so that a config blob
	// that fails to load still fails closed. It is flushed before the
	// config blob is written, so a crash between the two leaves the
	// marker set (fail closed) rather than cleared (fail open).
	const auto pinned = config.hasCustomServer();
	if (pinned != _hasStoredCustomServer) {
		writePref<bool>(kCustomServerPinnedPref, pinned);
		if (!writePrefs(sync)) {
			return false;
		}
		_hasStoredCustomServer = pinned;
	}

	const auto serialized = config.serialize();
	const auto size = Serialize::bytearraySize(serialized);

	FileWriteDescriptor file(u"config"_q, _basePath, sync);
	EncryptedDescriptor data(size);
	data.stream << serialized;
	file.writeEncrypted(data, _localKey);
	if (!file.finish()) {
		return false;
	}

	if (_customServerPinUnknown) {
		// A config was read and written this session, so whether this
		// account is pinned is no longer unknown. Left behind, it would
		// describe a later unreadable config as damaged local data.
		clearPref(kCustomServerPinUnknownPref);
		if (!writePrefs(sync)) {
			return false;
		}
		_customServerPinUnknown = false;
	}
	return true;
}

void Account::clearPref(std::string_view key) {
	const auto i = _prefs.find(QByteArray(key.data(), key.size()));
	if (i == end(_prefs)) {
		return;
	}
	_prefs.erase(i);
	writePrefsDelayed();
}

void Account::writePrefGeneric(
		std::string_view key,
		const QByteArray &value) {
	const auto raw = QByteArray(key.data(), key.size());
	if (const auto i = _prefs.find(raw); i != end(_prefs)) {
		if (i->second == value) {
			return;
		}
		i->second = value;
	} else {
		_prefs.emplace(raw, value);
	}
	writePrefsDelayed();
}

std::optional<QByteArray> Account::readPrefGeneric(std::string_view key) {
	const auto i = _prefs.find(QByteArray(key.data(), key.size()));
	return (i != end(_prefs)) ? i->second : std::optional<QByteArray>();
}

void Account::writePrefsDelayed() {
	_prefsChanged = true;
	_writePrefsTimer.callOnce(kDelayedWriteTimeout);
}

bool Account::writePrefs(bool sync) {
	_writePrefsTimer.cancel();
	if (!_prefsChanged) {
		return !sync || writeMap(true);
	}

	if (_prefs.empty()) {
		if (_prefsKey) {
			const auto oldKey = _prefsKey;
			_prefsKey = 0;
			_mapChanged = true;
			if (sync && !writeMap(true)) {
				_prefsKey = oldKey;
				return false;
			}
			if (!sync) {
				ClearKey(oldKey, _basePath);
				writeMapDelayed();
			} else {
				ClearKey(oldKey, _basePath);
			}
		}
		_prefsChanged = false;
		return !sync || writeMap(true);
	} else {
		if (!_prefsKey) {
			_prefsKey = GenerateKey(_basePath);
			if (sync) {
				_mapChanged = true;
			} else {
				writeMapQueued();
			}
		}
		quint32 size = sizeof(quint32);
		for (const auto &[key, value] : _prefs) {
			size += 2 * sizeof(quint32) + key.size() + value.size();
		}

		EncryptedDescriptor data(size);
		data.stream << quint32(_prefs.size());
		for (const auto &[key, value] : _prefs) {
			data.stream << quint32(key.size()) << quint32(value.size());
			data.stream.writeRawData(key.constData(), key.size());
			data.stream.writeRawData(value.constData(), value.size());
		}

		FileWriteDescriptor file(_prefsKey, _basePath, sync);
		file.writeEncrypted(data, _localKey);
		if (!file.finish()) {
			return false;
		}
	}
	_prefsChanged = false;
	return !sync || writeMap(true);
}

// Define your own pref types in the similar way.
template <>
std::optional<bool> Account::readPrefImpl<bool>(std::string_view key) {
	if (const auto data = readPrefGeneric(key)) {
		return !data->isEmpty();
	}
	return {};
}

template <>
void Account::writePrefImpl<bool>(std::string_view key, bool value) {
	writePrefGeneric(key, value ? "\x1"_q : QByteArray());
}

} // namespace Storage
