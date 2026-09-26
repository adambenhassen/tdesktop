/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QString>

namespace Ui::EditPeer {

constexpr auto kMaxGroupChannelTitle = 128;
constexpr auto kMaxUserFirstLastName = 64;
constexpr auto kMaxChannelDescription = 255;
constexpr auto kMinUsernameLength = 2;
constexpr auto kMaxUsernameLength = 32;
constexpr auto kMinBotUsernameLength = 5;
constexpr auto kUsernameCheckTimeout = crl::time(200);

class UsernameCheckState final {
public:
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
		_good = _unavailable && locallyValid;
	}

	[[nodiscard]] Request requestStarted() {
		return { ++_revision, _username };
	}

	[[nodiscard]] bool setAvailability(Request request, bool available) {
		if (!isCurrent(request)) {
			return false;
		}
		_good = available;
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
			return FailureResult::Unavailable;
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

	[[nodiscard]] bool unavailable() const {
		return _unavailable;
	}

	[[nodiscard]] bool shouldCheck() const {
		return !_unavailable;
	}

	void setGood(bool value) {
		_good = value;
	}

private:
	quint64 _revision = 0;
	QString _username;
	bool _good = false;
	bool _unavailable = false;

};

} // namespace Ui::EditPeer
