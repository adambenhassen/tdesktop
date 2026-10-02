/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "core/local_url_conversion.h"

namespace qthelp {
class RegularExpressionMatch;
} // namespace qthelp

namespace ChatHelpers {
class Show;
} // namespace ChatHelpers

namespace Main {
class Session;
} // namespace Main

namespace Settings {
struct CreditsEntryBoxStyleOverrides;
} // namespace Settings

namespace Window {
class SessionController;
} // namespace Window

namespace Core {

struct LocalUrlHandler {
	QString expression;
	Fn<bool(
		Window::SessionController *controller,
		const qthelp::RegularExpressionMatch &match,
		const QVariant &context)> handler;
};

[[nodiscard]] bool TryRouterForLocalUrl(
	Window::SessionController *controller,
	const QString &command);

[[nodiscard]] QString TryConvertUrlToLocal(
	QString url,
	const Main::Session *session);

[[nodiscard]] const std::vector<LocalUrlHandler> &LocalUrlHandlers();
[[nodiscard]] const std::vector<LocalUrlHandler> &InternalUrlHandlers();

[[nodiscard]] bool IsMiniAppUrl(const QString &url);

[[nodiscard]] bool InternalPassportOrOAuthLink(const QString &url);

[[nodiscard]] bool StartUrlRequiresActivate(const QString &url);

void ResolveAndShowUniqueGift(
	std::shared_ptr<ChatHelpers::Show> show,
	const QString &slug,
	::Settings::CreditsEntryBoxStyleOverrides st);
void ResolveAndShowUniqueGift(
	std::shared_ptr<ChatHelpers::Show> show,
	const QString &slug);

[[nodiscard]] TimeId ParseVideoTimestamp(QStringView value);

} // namespace Core
