/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "main/main_account.h"

#include "main/main_domain.h"
#include "mtproto/mtproto_config.h"
#include "storage/storage_account.h"
#include "storage/storage_domain.h"

#include <QtCore/QDir>

namespace Main {
namespace {

[[nodiscard]] QString SlotDataName(const QString &dataName, int index) {
	auto result = dataName;
	result.replace('#', QString());
	if (index > 0) {
		result += '#' + QString::number(index + 1);
	}
	return result;
}

} // namespace

QString Account::storageBasePathForTest(
		const QString &dataName,
		int index) {
	return QDir::currentPath()
		+ u"/tdata/account_"_q
		+ SlotDataName(dataName, index)
		+ '/';
}

QString Account::storageTempPathForTest(
		const QString &dataName,
		int index) {
	return QDir::currentPath()
		+ u"/tdata/temp_"_q
		+ SlotDataName(dataName, index)
		+ '/';
}

QString Account::storageDatabasePathForTest(
		const QString &dataName,
		int index) {
	return QDir::currentPath()
		+ u"/tdata/user_"_q
		+ SlotDataName(dataName, index)
		+ '/';
}

Account::Account(not_null<Domain*> domain, const QString &dataName, int index)
: _domain(domain)
, _local(std::make_unique<Storage::Account>(
	storageBasePathForTest(dataName, index),
	MTP::AuthKeyPtr(),
	std::make_shared<MTP::Config>(MTP::Environment::Production),
	false,
	[] { return QByteArray(); },
	nullptr,
	nullptr,
	storageTempPathForTest(dataName, index),
	storageDatabasePathForTest(dataName, index),
	Storage::FileKey(index + 1)))
, _testIndex(index) {
}

Account::~Account() {
	_local.reset();
	_mtp.release();
	_mtpForKeysDestroy.release();
	_appConfig.release();
	_session.release();
	_storedSessionSettings.release();
}

Storage::Domain &Account::domainLocal() const {
	return _domain->local();
}

Storage::StartResult Account::legacyStart(const QByteArray &) {
	return Storage::StartResult::Success;
}

std::unique_ptr<MTP::Config> Account::prepareToStart(
		std::shared_ptr<MTP::AuthKey> localKey) {
	if (_local->serverReenrollmentPending()) {
		return _local->startServerReenrollmentForTest(std::move(localKey));
	}
	return std::make_unique<MTP::Config>(MTP::Environment::Production);
}

void Account::prepareToStartAdded(std::shared_ptr<MTP::AuthKey>) {
}

void Account::start(std::unique_ptr<MTP::Config> config) {
	_testStartedUnenrolled = config
		&& config->dcOptions().unenrolled();
}

uint64 Account::willHaveSessionUniqueId(MTP::Config *) const {
	return (_testIndex == 0) ? uint64(42) : uint64(0);
}

bool Account::startedUnenrolledForTest() const {
	return _testStartedUnenrolled;
}

Domain::Domain(const QString &dataName)
: _dataName(dataName)
, _local(std::make_unique<Storage::Domain>(this, dataName)) {
}

Domain::~Domain() = default;

const std::vector<Domain::AccountWithIndex> &Domain::accounts() const {
	return _accounts;
}

void Domain::accountAddedInStorage(AccountWithIndex accountWithIndex) {
	_accounts.push_back(std::move(accountWithIndex));
}

void Domain::activateFromStorage(int index) {
	_accountToActivate = index;
}

int Domain::activeForStorage() const {
	return _accountToActivate;
}

} // namespace Main
