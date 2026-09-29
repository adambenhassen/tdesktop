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
