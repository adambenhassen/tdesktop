/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "storage/storage_account.h"

#include "base/const_string.h"
#include "main/main_account.h"
#include "mtproto/mtproto_config.h"
#include "storage/details/storage_file_utilities.h"
#include "storage/details/storage_settings_scheme.h"
#include "storage/serialize_common.h"
#include "storage/serialize_peer.h"
#include "settings.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>

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
constexpr auto kMtpAuthorizationWriteFailedPref
	= "mtp_authorization_write_failed"_cs;
const auto kMtpAuthorizationWriteFailedFile
	= u"mtp_authorization_write_failed"_q;
const auto kServerReenrollmentTombstonePrefix
	= u"server_reenrollment_"_q;

[[nodiscard]] QString BaseGlobalPath() {
#ifdef TDESKTOP_UNIT_TESTS
	return QDir::currentPath() + u"/tdata/"_q;
#else
	return cWorkingDir() + u"tdata/"_q;
#endif
}

[[nodiscard]] QString ServerReenrollmentTombstoneName(FileKey dataNameKey) {
	return kServerReenrollmentTombstonePrefix + ToFilePart(dataNameKey);
}

[[nodiscard]] bool RemoveFileVariants(
		const QString &basePath,
		const QString &name) {
	const auto base = basePath + name;
	auto result = true;
	for (const auto suffix : { 's', '0', '1' }) {
		const auto path = base + suffix;
		if (QFileInfo::exists(path) && !QFile::remove(path)) {
			result = false;
		}
	}
	return result;
}

[[nodiscard]] bool RemovePath(const QString &path) {
	if (path.isEmpty()) {
		return true;
	}
	const auto info = QFileInfo(path);
	if (!info.exists()) {
		return true;
	}
	return info.isDir()
		? QDir(path).removeRecursively()
		: QFile::remove(path);
}

[[nodiscard]] bool IsKnownWebviewPath(
		const QString &path,
		const QString &databasePath,
		const QString &globalPath) {
	return path.isEmpty()
		|| path == globalPath + u"webview"_q
		|| path == databasePath + u"wvbots"_q
		|| path == databasePath + u"wvother"_q;
}

[[nodiscard]] bool WriteMtpAuthorizationData(
		FileKey dataNameKey,
		const QString &basePath,
		const MTP::AuthKeyPtr &localKey,
		const QByteArray &serialized,
		bool sync) {
	const auto size = sizeof(quint32) + Serialize::bytearraySize(serialized);

	FileWriteDescriptor mtp(ToFilePart(dataNameKey), basePath, sync);
	EncryptedDescriptor data(size);
	data.stream << quint32(dbiMtpAuthorization) << serialized;
	mtp.writeEncrypted(data, localKey);
	return mtp.finish();
}

[[nodiscard]] std::optional<std::pair<QString, QString>>
ReadServerReenrollmentTombstone(
		FileKey dataNameKey,
		const QString &basePath,
		const MTP::AuthKeyPtr &localKey) {
	FileReadDescriptor marker;
	if (!ReadEncryptedFile(
			marker,
			ServerReenrollmentTombstoneName(dataNameKey),
			basePath,
			localKey)) {
		return std::nullopt;
	}

	quint32 version = 0;
	QString webviewBots;
	QString webviewOther;
	marker.stream >> version >> webviewBots >> webviewOther;
	if (!CheckStreamStatus(marker.stream) || version != 2) {
		return std::nullopt;
	}
	return std::make_pair(std::move(webviewBots), std::move(webviewOther));
}

} // namespace

#ifdef TDESKTOP_UNIT_TESTS

Account::Account(
		const QString &basePath,
		MTP::AuthKeyPtr localKey,
		std::shared_ptr<const MTP::Config> config,
		bool hasStoredCustomServer,
		Fn<QByteArray()> serializeMtpAuthorization,
		Fn<void(const QByteArray &)> restoreMtpAuthorization,
		Fn<bool()> writeMtpAuthorizationOverride,
		QString tempPath,
		QString databasePath,
		FileKey dataNameKey)
: _owner(nullptr)
, _dataNameKey(dataNameKey)
, _basePath(basePath.endsWith(QDir::separator())
	? basePath
	: basePath + QDir::separator())
, _tempPath(tempPath.isEmpty()
	? _basePath + u"temp/"_q
	: std::move(tempPath))
, _databasePath(databasePath.isEmpty()
	? _basePath + u"database/"_q
	: std::move(databasePath))
, _localKey(std::move(localKey))
, _hasStoredCustomServer(hasStoredCustomServer)
, _mtpConfig([config = std::move(config)]() -> const MTP::Config & {
	return *config;
})
, _serializeMtpAuthorization(std::move(serializeMtpAuthorization))
, _restoreMtpAuthorization(std::move(restoreMtpAuthorization))
, _writeMtpAuthorizationOverride(std::move(writeMtpAuthorizationOverride))
, _serializeSelf(nullptr)
, _queueMapWrite(nullptr)
, _writeMapTimer([this] { writeMap(); })
, _writePrefsTimer([this] { writePrefs(); }) {
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

bool Account::writeMtpAuthorization() {
#ifdef TDESKTOP_LIFECYCLE_REGRESSION
	if (qEnvironmentVariableIsSet(
			"TDESKTOP_FAIL_MTP_AUTHORIZATION_WRITE")) {
		return false;
	}
#endif
#ifdef TDESKTOP_UNIT_TESTS
	if (_writeMtpAuthorizationOverride) {
		return _writeMtpAuthorizationOverride();
	}
#endif
	if (!writeMtpConfig(true) || !writeMtpData(true)) {
		return false;
	}
	if (_mtpAuthorizationWriteFailed) {
		clearPref(kMtpAuthorizationWriteFailedPref);
		if (!writePrefs(true)) {
			return false;
		}
		if (!clearMtpAuthorizationFailureMarker()) {
			return false;
		}
		_mtpAuthorizationWriteFailed = false;
	}
	return true;
}

bool Account::writeMtpAuthorizationFailure() {
	Expects(_localKey != nullptr);

	writePref<bool>(kMtpAuthorizationWriteFailedPref, true);
	const auto prefsWritten = writePrefs(true);
	EncryptedDescriptor marker(sizeof(quint32));
	marker.stream << quint32(1);
	FileWriteDescriptor file(
		kMtpAuthorizationWriteFailedFile,
		_basePath,
		true);
	file.writeEncrypted(marker, _localKey);
	const auto markerWritten = file.finish();
	_mtpAuthorizationWriteFailed = true;
	return prefsWritten && markerWritten;
}

bool Account::writeMtpData(bool sync) {
	Expects(_localKey != nullptr);

#ifdef TDESKTOP_UNIT_TESTS
	Expects(_serializeMtpAuthorization != nullptr);
	const auto serialized = _serializeMtpAuthorization();
#else
	const auto serialized = _serializeMtpAuthorization
		? _serializeMtpAuthorization()
		: _owner->serializeMtpAuthorization();
#endif
	return WriteMtpAuthorizationData(
		_dataNameKey,
		BaseGlobalPath(),
		_localKey,
		serialized,
		sync);
}

bool Account::writeServerReenrollmentTombstone() {
	Expects(_localKey != nullptr);

	const auto webviewBots = (!_webviewStorageIdBots.token.isEmpty())
		? (_webviewStorageIdBots.path.isEmpty()
			? ((_webviewStorageIdBots.token == Webview::LegacyStorageIdToken())
				? BaseGlobalPath() + u"webview"_q
				: _databasePath + u"wvbots"_q)
			: _webviewStorageIdBots.path)
		: QString();
	const auto webviewOther = (!_webviewStorageIdOther.token.isEmpty())
		? (_webviewStorageIdOther.path.isEmpty()
			? _databasePath + u"wvother"_q
			: _webviewStorageIdOther.path)
		: QString();
	if (!IsKnownWebviewPath(webviewBots, _databasePath, BaseGlobalPath())
		|| !IsKnownWebviewPath(
			webviewOther,
			_databasePath,
			BaseGlobalPath())) {
		return false;
	}

	EncryptedDescriptor marker(
		sizeof(quint32)
		+ Serialize::stringSize(webviewBots)
		+ Serialize::stringSize(webviewOther));
	marker.stream << quint32(2) << webviewBots << webviewOther;
	FileWriteDescriptor file(
		ServerReenrollmentTombstoneName(_dataNameKey),
		BaseGlobalPath(),
		true);
	file.writeEncrypted(marker, _localKey);
	return file.finish();
}

bool Account::serverReenrollmentPending() const {
	const auto name = ServerReenrollmentTombstoneName(_dataNameKey);
	const auto base = BaseGlobalPath() + name;
	return QFileInfo::exists(base + 's')
		|| QFileInfo::exists(base + '0')
		|| QFileInfo::exists(base + '1');
}

std::unique_ptr<MTP::Config> Account::startServerReenrollment() {
	Expects(_localKey != nullptr);
	// Do not read even the map or authorization file while the durable wipe
	// is pending. If the previous launch stopped during cleanup, complete it
	// before this account can become usable again.
	if (!completeServerReenrollment()) {
		LOG(("MTP Error: server re-enrollment cleanup is still pending."));
		auto blocked = std::make_unique<MTP::Config>(
			MTP::Environment::Production);
		blocked->dcOptions().constructBlocked();
		return blocked;
	}
	auto unenrolled = std::make_unique<MTP::Config>(
			MTP::Environment::Production);
	unenrolled->dcOptions().constructUnenrolled();
	return unenrolled;
}

bool Account::completeServerReenrollment() {
	Expects(_localKey != nullptr);
	if (!serverReenrollmentPending()) {
		return true;
	}
	const auto tombstone = ReadServerReenrollmentTombstone(
		_dataNameKey,
		BaseGlobalPath(),
		_localKey);
	if (!tombstone) {
		return false;
	}
	_writeMapTimer.cancel();
	_writePrefsTimer.cancel();
	_writeLocationsTimer.cancel();
	_writeSearchSuggestionsTimer.cancel();
	_mapChanged = false;
	_prefsChanged = false;
	_locationsChanged = false;

#ifdef TDESKTOP_UNIT_TESTS
	const auto interrupted = [this](int point) {
		if (_serverReenrollmentInterruptionForTest != point) {
			return false;
		}
		_serverReenrollmentInterruptionForTest = 0;
		return true;
	};
#else
	const auto interrupted = [](int) {
		return false;
	};
#endif

	// The tombstone lives beside, not inside, the account directory. A
	// process stop after this removal therefore cannot make the next launch
	// mistake a partly deleted account for a clean one.
	if (!RemovePath(_basePath) || interrupted(1)) {
		return false;
	}

	const auto &[webviewBots, webviewOther] = *tombstone;
	if (!IsKnownWebviewPath(webviewBots, _databasePath, BaseGlobalPath())
		|| !IsKnownWebviewPath(
			webviewOther,
			_databasePath,
			BaseGlobalPath())) {
		return false;
	}
	// The legacy tdata/tdld directory predates per-account storage and is
	// shared by every account. It has no ownership marker, so leave it
	// intact rather than deleting another account's data.
	if (!RemovePath(_databasePath)
		|| !RemovePath(_tempPath)
		|| !RemovePath(webviewBots)
		|| !RemovePath(webviewOther)
		|| !RemoveFileVariants(
			BaseGlobalPath(),
			ToFilePart(_dataNameKey))) {
		return false;
	}
	if (interrupted(2)) {
		return false;
	}

	_draftsMap.clear();
	_draftCursorsMap.clear();
	_draftsNotReadMap.clear();
	_botStoragesMap.clear();
	_botStoragesNotReadMap.clear();
	_fileLocations.clear();
	_fileLocationPairs.clear();
	_fileLocationAliases.clear();
	_downloadsSerialized.clear();
	_downloadsSerialize = nullptr;
	_trustedPeers.clear();
	_trustedPayPerMessage.clear();
	_trustedPeersRead = false;
	_readingUserSettings = false;
	_recentHashtagsAndBotsWereRead = false;
	_searchSuggestionsRead = false;
	_inlineBotsDownloadsRead = false;
	_mediaLastPlaybackPositionsRead = false;
	_mediaLastPlaybackPosition.clear();
	_roundPlaceholder = QImage();
	_webviewStorageIdBots = {};
	_webviewStorageIdOther = {};
	_prefs.clear();
	_prefsKey = 0;
	_locationsKey = 0;
	_trustedPeersKey = 0;
	_installedStickersKey = 0;
	_featuredStickersKey = 0;
	_recentStickersKey = 0;
	_favedStickersKey = 0;
	_archivedStickersKey = 0;
	_archivedMasksKey = 0;
	_savedGifsKey = 0;
	_recentStickersKeyOld = 0;
	_legacyBackgroundKeyDay = 0;
	_legacyBackgroundKeyNight = 0;
	_settingsKey = 0;
	_recentHashtagsAndBotsKey = 0;
	_exportSettingsKey = 0;
	_installedMasksKey = 0;
	_recentMasksKey = 0;
	_installedCustomEmojiKey = 0;
	_featuredCustomEmojiKey = 0;
	_archivedCustomEmojiKey = 0;
	_searchSuggestionsKey = 0;
	_roundPlaceholderKey = 0;
	_inlineBotsDownloadsKey = 0;
	_mediaLastPlaybackPositionsKey = 0;
	_oldMapVersion = 0;
	_prefsReadFailed = false;
	_hasStoredCustomServer = false;
	_customServerPinUnknown = false;
	_mtpAuthorizationWriteFailed = false;
	_mapChanged = true;
	_prefsChanged = false;
	_locationsChanged = false;

	// Startup normally reaches this method before a map has populated the
	// self callback. Clear it for the same-account test path as well, so a
	// failed or interrupted wipe can never write an old self record back.
	auto serializeSelf = base::take(_serializeSelf);
	const auto mapWritten = writeMap(true);
	_serializeSelf = std::move(serializeSelf);
	if (!mapWritten
		|| !WriteMtpAuthorizationData(
			_dataNameKey,
			BaseGlobalPath(),
			_localKey,
			QByteArray(),
			true)) {
		return false;
	}

	if (!RemoveFileVariants(
			BaseGlobalPath(),
			ServerReenrollmentTombstoneName(_dataNameKey))) {
		return false;
	}
	details::Sync();
	return true;
}

#ifdef TDESKTOP_UNIT_TESTS

std::unique_ptr<MTP::Config> Account::startServerReenrollmentForTest(
		MTP::AuthKeyPtr localKey) {
	_localKey = std::move(localKey);
	return startServerReenrollment();
}

void Account::setServerReenrollmentInterruptionForTest(int point) {
	_serverReenrollmentInterruptionForTest = point;
}

#endif // TDESKTOP_UNIT_TESTS

#ifdef TDESKTOP_UNIT_TESTS

void Account::readMtpDataForTest() {
	FileReadDescriptor mtp;
	if (!ReadEncryptedFile(
			mtp,
			ToFilePart(_dataNameKey),
			BaseGlobalPath(),
			_localKey)) {
		return;
	}

	while (!mtp.stream.atEnd()) {
		quint32 blockId = 0;
		mtp.stream >> blockId;
		if (!CheckStreamStatus(mtp.stream)
			|| blockId != dbiMtpAuthorization) {
			return;
		}
		QByteArray serialized;
		mtp.stream >> serialized;
		if (!CheckStreamStatus(mtp.stream)) {
			return;
		}
		if (_restoreMtpAuthorization) {
			_restoreMtpAuthorization(serialized);
		}
		return;
	}
}

void Account::readMtpAuthorizationFailureMarkerForTest() {
	readMtpAuthorizationFailureMarker();
}

#endif // TDESKTOP_UNIT_TESTS

void Account::readMtpAuthorizationFailureMarker() {
	const auto base = _basePath + kMtpAuthorizationWriteFailedFile;
	const auto exists = QFileInfo::exists(base + 's')
		|| QFileInfo::exists(base + '0')
		|| QFileInfo::exists(base + '1');
	if (!exists) {
		return;
	}

	FileReadDescriptor marker;
	if (!ReadEncryptedFile(
			marker,
			kMtpAuthorizationWriteFailedFile,
			_basePath,
			_localKey)) {
		_mtpAuthorizationWriteFailed = true;
		return;
	}
	quint32 value = 0;
	marker.stream >> value;
	if (!CheckStreamStatus(marker.stream) || value != 1) {
		// A marker file is evidence that a final authorization write was
		// attempted. Treat a damaged marker as failed closed too.
		_mtpAuthorizationWriteFailed = true;
		return;
	}
	_mtpAuthorizationWriteFailed = true;
}

bool Account::clearMtpAuthorizationFailureMarker() {
	const auto base = _basePath + kMtpAuthorizationWriteFailedFile;
	auto result = true;
	for (const auto suffix : { 's', '0', '1' }) {
		const auto path = base + suffix;
		if (QFileInfo::exists(path) && !QFile::remove(path)) {
			result = false;
		}
	}
	return result;
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
