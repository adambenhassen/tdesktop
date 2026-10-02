/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QString>

namespace Core {

[[nodiscard]] QString TryConvertUrlToLocal(QString url);
[[nodiscard]] QString TryConvertUrlToLocal(
	QString url,
	const QString &internalLinksDomain,
	bool hasPinnedServer);

} // namespace Core
