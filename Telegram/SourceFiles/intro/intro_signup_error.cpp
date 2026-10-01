/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "intro/intro_signup_error.h"

#include "intro/intro_username_validation.h"

namespace Intro::details {

SignupFailureDecision ClassifySignupFailure(
		const QString &errorType,
		int errorCode,
		bool floodError,
		bool reissuedOnce) {
	auto result = SignupFailureDecision();
	result.backAvailable = errorCode >= 400 && errorCode < 500;
	if (!result.backAvailable) {
		return result;
	} else if (floodError) {
		result.message = SignupFailureMessage::FloodWait;
		result.floodWaitSeconds = FloodWaitSeconds(errorType);
	} else if (errorType == u"INPUT_REQUEST_INVALID"_q) {
		result.message = SignupFailureMessage::RegistrationClosed;
	} else if (errorType == u"USERNAME_OCCUPIED"_q) {
		result.message = SignupFailureMessage::UsernameTaken;
	} else if (errorType == u"USERNAME_INVALID"_q) {
		result.message = SignupFailureMessage::UsernameInvalid;
		result.destination = SignupFailureDestination::Username;
		result.action = SignupFailureAction::ReturnToInput;
	} else if (errorType == u"PHONE_NUMBER_INVALID"_q) {
		result.message = SignupFailureMessage::UsernameUnavailable;
		result.destination = SignupFailureDestination::Username;
		result.action = SignupFailureAction::ReturnToInput;
	} else if (errorType == u"FIRSTNAME_INVALID"_q
		|| errorType == u"LASTNAME_INVALID"_q) {
		result.message = SignupFailureMessage::NameInvalid;
		result.destination = SignupFailureDestination::Name;
		result.action = SignupFailureAction::ReturnToInput;
	} else if (errorType == u"INVITE_HASH_INVALID"_q) {
		result.message = SignupFailureMessage::InvitationUnavailable;
	} else if (errorType == u"SESSION_STATE_INVALID"_q) {
		result.message = SignupFailureMessage::SessionCannotContinue;
	} else if (errorType == u"PHONE_CODE_INVALID"_q
		|| errorType == u"PHONE_CODE_EXPIRED"_q) {
		result.message = SignupFailureMessage::CodeTicketExpired;
		if (!reissuedOnce) {
			result.action = SignupFailureAction::ReissueCode;
		}
	}
	return result;
}

} // namespace Intro::details
