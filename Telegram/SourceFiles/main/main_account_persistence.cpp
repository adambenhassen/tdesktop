/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "main/main_account_persistence.h"

#include "storage/storage_account.h"

namespace Main::details {
bool CommitServerReenrollment(
		ServerReenrollmentPrompt prompt,
		bool accepted,
		Fn<bool()> commit) {
	if (prompt != ServerReenrollmentPrompt::DestructiveConfirmation
		|| !accepted) {
		return false;
	}
	return commit();
}

bool ShouldBlockRestoredSessionWithoutServerPin(
		bool hasRestoredUserId,
		bool hasReadableServerPin) {
	return hasRestoredUserId && !hasReadableServerPin;
}

bool CommitServerForget(
		not_null<Storage::Account*> local,
		Storage::ServerCacheBinding binding,
		Fn<void()> restart) {
	if (!local->beginServerForget(std::move(binding))) {
		return false;
	}
	restart();
	return true;
}

bool CommitPostAuthMtpAuthorization(
		not_null<Storage::Account*> local,
		Fn<void()> committed,
		Fn<void()> failed) {
	if (!local->writeMtpAuthorization()) {
		failed();
		return false;
	}
	committed();
	return true;
}

bool CommitTeardownMtpAuthorization(
		not_null<Storage::Account*> local,
		Fn<void()> committed,
		Fn<void()> failed) {
	if (!local->writeMtpAuthorization()) {
		failed();
		return false;
	}
	committed();
	return true;
}

} // namespace Main::details
