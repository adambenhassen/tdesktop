/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "data/data_peer_id.h"

#include <QtCore/QString>

#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

namespace Data::details {

[[nodiscard]] inline constexpr bool CanAddBasicChatAdmins(
		bool isMember,
		bool isCreator) {
	return isMember && isCreator;
}

struct ChatParticipantInfo {
	UserId userId;
	UserId inviterId;
	bool creator = false;
	bool admin = false;
	QString rank;
};

template <typename User>
struct ResolvedChatParticipant {
	ChatParticipantInfo participant;
	User user;
};

template <typename Resolve>
[[nodiscard]] auto ResolveChatParticipants(
		const std::vector<ChatParticipantInfo> &participants,
		Resolve &&resolve)
-> std::optional<std::vector<ResolvedChatParticipant<
	typename std::invoke_result_t<Resolve &, UserId>::value_type>>> {
	using User = typename std::invoke_result_t<Resolve &, UserId>::value_type;
	auto result = std::vector<ResolvedChatParticipant<User>>();
	result.reserve(participants.size());
	for (const auto &participant : participants) {
		auto user = resolve(participant.userId);
		if (!user) {
			return std::nullopt;
		}
		result.push_back({ participant, std::move(*user) });
	}
	return result;
}

} // namespace Data::details
