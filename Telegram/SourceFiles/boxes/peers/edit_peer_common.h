/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QString>

#include <optional>
#include <utility>

namespace Ui::EditPeer {

constexpr auto kMaxGroupChannelTitle = 128;
constexpr auto kMaxUserFirstLastName = 64;
constexpr auto kMaxChannelDescription = 255;
constexpr auto kMinUsernameLength = 2;
constexpr auto kMaxUsernameLength = 32;
constexpr auto kMinBotUsernameLength = 5;
constexpr auto kUsernameCheckTimeout = crl::time(200);

class UsernameEditorFlow final {
public:
	enum class Status {
		Default,
		Pending,
		Good,
		Error,
		Unavailable,
	};

	enum class FailureResult {
		Ignored,
		Handled,
		Unavailable,
	};

	struct Request {
		quint64 revision = 0;
		QString username;
	};

	void inputChanged(const QString &username, bool locallyValid) {
		++_revision;
		_username = username;
		_locallyValid = locallyValid;
		_good = _unavailable && locallyValid;
		_status = _unavailable
			? Status::Unavailable
			: (locallyValid ? Status::Default : Status::Error);
	}

	[[nodiscard]] std::optional<Request> requestStarted(bool force = false) {
		if (!shouldCheck() || (!force && !_locallyValid)) {
			return std::nullopt;
		}
		_status = Status::Pending;
		return Request{ ++_revision, _username };
	}

	template <typename Send, typename Done, typename Fail>
	[[nodiscard]] bool check(
			const QString &checking,
			bool force,
			bool trackAvailability,
			Send send,
			Done done,
			Fail fail) {
		const auto request = requestStarted(force);
		if (!request) {
			return false;
		}
		const auto token = *request;
		send(
			checking,
			[this, token, trackAvailability, done = std::move(done)](
					bool available) mutable {
				if (!isCurrent(token)) {
					return;
				}
				if (trackAvailability
					&& !availabilitySucceeded(token, available)) {
					return;
				}
				done(available);
			},
			[this, token, fail = std::move(fail)](
					const QString &error) mutable {
				const auto current = isCurrent(token);
				const auto result = availabilityFailed(token, error);
				if (result != FailureResult::Ignored) {
					fail(error, result, current);
				}
			});
		return true;
	}

	[[nodiscard]] bool availabilitySucceeded(
			Request request,
			bool available) {
		if (!isCurrent(request)) {
			return false;
		}
		_good = available;
		_status = available ? Status::Good : Status::Error;
		return true;
	}

	[[nodiscard]] FailureResult availabilityFailed(
			Request request,
			const QString &error) {
		const auto unavailable = (error == u"INPUT_METHOD_INVALID"_q);
		if (!isCurrent(request) && !unavailable) {
			return FailureResult::Ignored;
		} else if (unavailable) {
			_unavailable = true;
			_status = Status::Unavailable;
			return FailureResult::Unavailable;
		} else {
			_status = Status::Error;
		}
		return FailureResult::Handled;
	}

	[[nodiscard]] bool isCurrent(Request request) const {
		return (request.revision == _revision)
			&& (request.username == _username);
	}

	[[nodiscard]] bool good() const {
		return _good;
	}

	[[nodiscard]] Status status() const {
		return _status;
	}

	[[nodiscard]] bool unavailable() const {
		return _unavailable;
	}

	[[nodiscard]] bool shouldCheck() const {
		return !_unavailable;
	}

	void setGood(bool value) {
		_good = value;
		_status = value ? Status::Good : Status::Error;
	}

	void setStatus(Status value) {
		_status = value;
	}

	template <typename Update>
	[[nodiscard]] bool trySave(bool requireGood, Update update) const {
		if (requireGood && !_good) {
			return false;
		}
		update(_username);
		return true;
	}

private:
	quint64 _revision = 0;
	QString _username;
	bool _good = false;
	bool _unavailable = false;
	bool _locallyValid = false;
	Status _status = Status::Default;

};

} // namespace Ui::EditPeer
