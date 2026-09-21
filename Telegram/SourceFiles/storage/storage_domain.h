/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/flat_map.h"

#include <QtCore/QDataStream>

#include <optional>
#include <vector>

namespace MTP {
class Config;
class AuthKey;
using AuthKeyPtr = std::shared_ptr<AuthKey>;
} // namespace MTP

namespace Main {
class Account;
class Domain;
} // namespace Main

namespace Storage {

enum class StartResult : uchar {
	Success,
	IncorrectPasscode,
	IncorrectPasscodeLegacy,
};

namespace details {

struct AccountListEntry final {
	int index = 0;
	bool isLast = false;
};

struct AccountList final {
	std::vector<AccountListEntry> entries;
	int active = 0;
	bool hasActive = false;
};

[[nodiscard]] inline std::optional<AccountList> ReadAccountList(
		QDataStream &stream,
		int maxAccounts) {
	auto result = AccountList();
	auto count = qint32();
	stream >> count;
	if (stream.status() != QDataStream::Ok
		|| count <= 0
		|| count > maxAccounts) {
		return std::nullopt;
	}

	auto tried = base::flat_set<int>();
	result.entries.reserve(count);
	for (auto i = 0; i != count; ++i) {
		auto index = qint32();
		stream >> index;
		if (stream.status() != QDataStream::Ok) {
			return std::nullopt;
		}
		if (index >= 0
			&& index < maxAccounts
			&& tried.emplace(index).second) {
			result.entries.push_back({
				.index = index,
				.isLast = (i + 1 == count),
			});
		}
	}
	if (!stream.atEnd()) {
		stream >> result.active;
		if (stream.status() != QDataStream::Ok) {
			return std::nullopt;
		}
		result.hasActive = true;
	}
	return result;
}

[[nodiscard]] inline bool ShouldKeepAccountOnStartup(
		uint64 sessionId,
		bool pendingServerReenrollment,
		bool noSessionRestored,
		bool isLastAccount) {
	return sessionId != 0
		|| pendingServerReenrollment
		|| (noSessionRestored && isLastAccount);
}

class AccountStartupSelector final {
public:
	[[nodiscard]] bool keep(
			uint64 sessionId,
			bool pendingServerReenrollment,
			bool isLastAccount) {
		if (!ShouldKeepAccountOnStartup(
				sessionId,
				pendingServerReenrollment,
				_sessions.empty(),
				isLastAccount)) {
			return false;
		}
		if (pendingServerReenrollment) {
			_sessions.emplace(sessionId);
		} else if (!_sessions.emplace(sessionId).second) {
			return false;
		}
		return true;
	}

	[[nodiscard]] bool empty() const {
		return _sessions.empty();
	}

private:
	base::flat_set<uint64> _sessions;
};

} // namespace details

class Domain final {
public:
	Domain(not_null<Main::Domain*> owner, const QString &dataName);
	~Domain();

	[[nodiscard]] StartResult start(const QByteArray &passcode);
	void startAdded(
		not_null<Main::Account*> account,
		std::unique_ptr<MTP::Config> config);
	void writeAccounts();
	void startFromScratch();

	[[nodiscard]] bool checkPasscode(const QByteArray &passcode) const;
	void setPasscode(const QByteArray &passcode);

	[[nodiscard]] int oldVersion() const;
	void clearOldVersion();

	[[nodiscard]] rpl::producer<> localPasscodeChanged() const;
	[[nodiscard]] bool hasLocalPasscode() const;

private:
	enum class StartModernResult {
		Success,
		IncorrectPasscode,
		Failed,
		Empty,
	};

	[[nodiscard]] StartModernResult startModern(const QByteArray &passcode);
	void startWithSingleAccount(
		const QByteArray &passcode,
		std::unique_ptr<Main::Account> account);
	void generateLocalKey();
	void encryptLocalKey(const QByteArray &passcode);

	const not_null<Main::Domain*> _owner;
	const QString _dataName;

	MTP::AuthKeyPtr _localKey;
	MTP::AuthKeyPtr _passcodeKey;
	QByteArray _passcodeKeySalt;
	QByteArray _passcodeKeyEncrypted;
	int _oldVersion = 0;

	bool _hasLocalPasscode = false;
	rpl::event_stream<> _passcodeKeyChanged;

};

} // namespace Storage
