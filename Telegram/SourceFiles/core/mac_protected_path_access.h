/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "core/mac_protected_path_runtime.h"

#include <QtCore/QFile>

#include <utility>

namespace Core::MacProtectedPath {

class PersistedExternalPath final {
  public:
	explicit PersistedExternalPath(QString stored)
		: _stored(std::move(stored)) {}

	[[nodiscard]] const QString &stored() const { return _stored; }

	template <typename Checker>
	[[nodiscard]] bool allowed(Operation operation, const char *callsite,
							   Checker &&checker) const {
		return _stored.isEmpty()
			   || std::forward<Checker>(checker)(operation, _stored, callsite);
	}

	[[nodiscard]] bool allowed(Operation operation,
							   const char *callsite) const {
		return allowed(
			operation, callsite,
			[](Operation checkedOperation, const QString &checkedPath,
			   const char *checkedCallsite) {
				return CheckExternalPath(checkedOperation, checkedPath,
										 checkedCallsite);
			});
	}

	template <typename Checker>
	[[nodiscard]] QString forUse(Operation operation, const char *callsite,
								 Checker &&checker) const {
		return allowed(operation, callsite, std::forward<Checker>(checker))
				   ? _stored
				   : QString();
	}

	[[nodiscard]] QString forUse(Operation operation,
								 const char *callsite) const {
		return allowed(operation, callsite) ? _stored : QString();
	}

  private:
	QString _stored;
};

template <typename Checker>
[[nodiscard]] bool OpenExternalFile(QFile &file, QIODevice::OpenMode mode,
									Operation operation, const char *callsite,
									Checker &&checker) {
	const auto path = file.fileName();
	return !path.isEmpty()
		   && PersistedExternalPath(path).allowed(
			   operation, callsite, std::forward<Checker>(checker))
		   && file.open(mode);
}

[[nodiscard]] inline bool OpenExternalFile(QFile &file,
										   QIODevice::OpenMode mode,
										   Operation operation,
										   const char *callsite) {
	return OpenExternalFile(
		file, mode, operation, callsite,
		[](Operation checkedOperation, const QString &checkedPath,
		   const char *checkedCallsite) {
			return CheckExternalPath(checkedOperation, checkedPath,
									 checkedCallsite);
		});
}

} // namespace Core::MacProtectedPath
