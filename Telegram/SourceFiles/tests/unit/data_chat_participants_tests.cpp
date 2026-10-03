/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "data/data_chat_participants.h"
#include "data/data_user_loading.h"

namespace {

using Data::details::ChatParticipantInfo;
using Data::details::ResolveChatParticipants;
using Data::details::CanMarkUserLoadedNormally;
using Data::details::CanAddBasicChatAdmins;
using Data::details::CanManageBasicChatCall;
using Data::details::BasicChatRole;

auto ResolveForAccount(
		const std::vector<ChatParticipantInfo> &participants,
		UserId self,
		bool pinned,
		bool selfHasPhone = false) {
	return ResolveChatParticipants(participants, [=](UserId id)
			-> std::optional<UserId> {
		const auto isSelf = (id == self);
		if (!CanMarkUserLoadedNormally(
				isSelf,
				isSelf && selfHasPhone,
				pinned)) {
			return std::nullopt;
		}
		return id;
	});
}

} // namespace

TEST_CASE(BasicGroupAdminPromotionRequiresCreatorMembership) {
	CHECK(CanAddBasicChatAdmins(true, true));
	CHECK(!CanAddBasicChatAdmins(false, true));
	CHECK(!CanAddBasicChatAdmins(true, false));
}

TEST_CASE(BasicGroupCallManagementRespectsServerAdminRights) {
	CHECK(CanManageBasicChatCall(BasicChatRole::Creator, false));
	CHECK(CanManageBasicChatCall(BasicChatRole::Creator, true));
	CHECK(CanManageBasicChatCall(BasicChatRole::Admin, false));
	CHECK(!CanManageBasicChatCall(BasicChatRole::Admin, true));
	CHECK(!CanManageBasicChatCall(BasicChatRole::Member, false));
	CHECK(!CanManageBasicChatCall(BasicChatRole::Member, true));
}

TEST_CASE(PinnedPhoneFreeSelfMemberKeepsGroupParticipants) {
	const auto participants = std::vector<ChatParticipantInfo>{
		{ .userId = UserId(2), .creator = true },
		{ .userId = UserId(1), .inviterId = UserId(2) },
		{ .userId = UserId(9), .inviterId = UserId(1) },
	};
	const auto resolved = ResolveForAccount(
		participants,
		UserId(1),
		true);
	CHECK(resolved.has_value());
	CHECK(resolved->size() == 3);
	CHECK((*resolved)[0].participant.userId == UserId(2));
	CHECK((*resolved)[1].participant.userId == UserId(1));
	CHECK((*resolved)[2].participant.userId == UserId(9));
	CHECK((*resolved)[0].participant.creator);
}

TEST_CASE(PinnedPhoneFreeSelfCreatorKeepsOwner) {
	const auto participants = std::vector<ChatParticipantInfo>{
		{ .userId = UserId(1), .creator = true },
		{ .userId = UserId(2), .inviterId = UserId(1) },
		{ .userId = UserId(9), .inviterId = UserId(1) },
	};
	const auto resolved = ResolveForAccount(
		participants,
		UserId(1),
		true);
	CHECK(resolved.has_value());
	CHECK(resolved->size() == 3);
	CHECK((*resolved)[0].participant.userId == UserId(1));
	CHECK((*resolved)[0].participant.creator);
}

TEST_CASE(StockPhoneFreeSelfDoesNotLoadGroupParticipants) {
	const auto participants = std::vector<ChatParticipantInfo>{
		{ .userId = UserId(2), .creator = true },
		{ .userId = UserId(1), .inviterId = UserId(2) },
		{ .userId = UserId(9), .inviterId = UserId(1) },
	};
	CHECK(!ResolveForAccount(participants, UserId(1), false));
	CHECK(ResolveForAccount(participants, UserId(1), false, true).has_value());
}
