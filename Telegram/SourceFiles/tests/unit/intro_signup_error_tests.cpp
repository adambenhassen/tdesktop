/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "intro/intro_signup_error.h"

namespace {

using namespace Intro::details;

TEST_CASE(SignupFailureRoutesUsernameAndNameValidation) {
	const auto username = ClassifySignupFailure(
		u"USERNAME_INVALID"_q,
		400,
		false,
		false);
	CHECK(username.message == SignupFailureMessage::UsernameInvalid);
	CHECK(username.destination == SignupFailureDestination::Username);
	CHECK(username.action == SignupFailureAction::ReturnToInput);
	CHECK(username.backAvailable);

	const auto unavailable = ClassifySignupFailure(
		u"PHONE_NUMBER_INVALID"_q,
		400,
		false,
		false);
	CHECK(unavailable.message == SignupFailureMessage::UsernameUnavailable);
	CHECK(unavailable.destination == SignupFailureDestination::Username);
	CHECK(unavailable.action == SignupFailureAction::ReturnToInput);
	CHECK(unavailable.backAvailable);

	for (const auto &type : { u"FIRSTNAME_INVALID"_q, u"LASTNAME_INVALID"_q }) {
		const auto name = ClassifySignupFailure(type, 400, false, false);
		CHECK(name.message == SignupFailureMessage::NameInvalid);
		CHECK(name.destination == SignupFailureDestination::Name);
		CHECK(name.action == SignupFailureAction::ReturnToInput);
		CHECK(name.backAvailable);
	}
}

TEST_CASE(SignupFailureKeepsRegistrationClosedAndUsernameTakenMessages) {
	const auto closed = ClassifySignupFailure(
		u"INPUT_REQUEST_INVALID"_q,
		400,
		false,
		false);
	CHECK(closed.message == SignupFailureMessage::RegistrationClosed);
	CHECK(closed.destination == SignupFailureDestination::Password);
	CHECK(closed.action == SignupFailureAction::ShowError);
	CHECK(closed.backAvailable);

	const auto taken = ClassifySignupFailure(
		u"USERNAME_OCCUPIED"_q,
		400,
		false,
		false);
	CHECK(taken.message == SignupFailureMessage::UsernameTaken);
	CHECK(taken.destination == SignupFailureDestination::Password);
	CHECK(taken.action == SignupFailureAction::ShowError);
	CHECK(taken.backAvailable);
}

TEST_CASE(SignupInviteAndSessionFailuresStayOnThePasswordStep) {
	const auto invite = ClassifySignupFailure(
		u"INVITE_HASH_INVALID"_q,
		400,
		false,
		false);
	CHECK(invite.message == SignupFailureMessage::InvitationUnavailable);
	CHECK(invite.destination == SignupFailureDestination::Password);
	CHECK(invite.action == SignupFailureAction::ShowError);
	CHECK(invite.backAvailable);

	const auto session = ClassifySignupFailure(
		u"SESSION_STATE_INVALID"_q,
		400,
		false,
		false);
	CHECK(session.message == SignupFailureMessage::SessionCannotContinue);
	CHECK(session.destination == SignupFailureDestination::Password);
	CHECK(session.action == SignupFailureAction::ShowError);
	CHECK(session.backAvailable);
}

TEST_CASE(SignupCodeTicketIsReissuedAtMostOnce) {
	for (const auto &type : { u"PHONE_CODE_INVALID"_q, u"PHONE_CODE_EXPIRED"_q }) {
		const auto first = ClassifySignupFailure(type, 400, false, false);
		CHECK(first.message == SignupFailureMessage::CodeTicketExpired);
		CHECK(first.destination == SignupFailureDestination::Password);
		CHECK(first.action == SignupFailureAction::ReissueCode);
		CHECK(first.backAvailable);

		const auto second = ClassifySignupFailure(type, 400, false, true);
		CHECK(second.message == SignupFailureMessage::CodeTicketExpired);
		CHECK(second.destination == SignupFailureDestination::Password);
		CHECK(second.action == SignupFailureAction::ShowError);
		CHECK(second.backAvailable);
	}
}

TEST_CASE(SignupFloodAndUnexpectedErrorsKeepTheirRecoveryBehavior) {
	const auto flood = ClassifySignupFailure(
		u"FLOOD_WAIT_3600"_q,
		420,
		true,
		false);
	CHECK(flood.message == SignupFailureMessage::FloodWait);
	CHECK(flood.destination == SignupFailureDestination::Password);
	CHECK(flood.action == SignupFailureAction::ShowError);
	CHECK(flood.backAvailable);
	CHECK_EQ(flood.floodWaitSeconds, 3600);

	const auto rejected = ClassifySignupFailure(
		u"OTHER_REJECTION"_q,
		400,
		false,
		false);
	CHECK(rejected.message == SignupFailureMessage::ServerError);
	CHECK(rejected.destination == SignupFailureDestination::Password);
	CHECK(rejected.action == SignupFailureAction::ShowError);
	CHECK(rejected.backAvailable);

	const auto failed = ClassifySignupFailure(
		u"OTHER_FAILURE"_q,
		500,
		false,
		false);
	CHECK(failed.message == SignupFailureMessage::ServerError);
	CHECK(failed.destination == SignupFailureDestination::Password);
	CHECK(failed.action == SignupFailureAction::ShowError);
	CHECK(!failed.backAvailable);

	const auto transport = ClassifySignupFailure(
		u"NETWORK_ERROR"_q,
		-1,
		false,
		false);
	CHECK(transport.message == SignupFailureMessage::ServerError);
	CHECK(transport.destination == SignupFailureDestination::Password);
	CHECK(transport.action == SignupFailureAction::ShowError);
	CHECK(!transport.backAvailable);
}

} // namespace
