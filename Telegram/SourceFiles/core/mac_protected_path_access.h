/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "core/mac_protected_path_runtime.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QUrl>

#include <functional>
#include <optional>
#include <utility>

namespace Core::MacProtectedPath {

#ifdef TDESKTOP_UNIT_TESTS
using ExternalPathChecker
	= std::function<bool(Operation, const QString &, const char *)>;

inline const ExternalPathChecker *&ExternalPathCheckerForTesting() {
	static thread_local const ExternalPathChecker *checker = nullptr;
	return checker;
}

class ScopedExternalPathCheckerForTesting final {
  public:
	explicit ScopedExternalPathCheckerForTesting(ExternalPathChecker checker)
		: _checker(std::move(checker)),
		  _previous(ExternalPathCheckerForTesting()) {
		ExternalPathCheckerForTesting() = &_checker;
	}

	~ScopedExternalPathCheckerForTesting() {
		ExternalPathCheckerForTesting() = _previous;
	}

	ScopedExternalPathCheckerForTesting(
		const ScopedExternalPathCheckerForTesting &) = delete;
	ScopedExternalPathCheckerForTesting &
	operator=(const ScopedExternalPathCheckerForTesting &) = delete;

  private:
	ExternalPathChecker _checker;
	const ExternalPathChecker *_previous = nullptr;
};
#endif // TDESKTOP_UNIT_TESTS

[[nodiscard]] inline bool CheckExternalPathForUse(Operation operation,
												  const QString &path,
												  const char *callsite) {
#ifdef TDESKTOP_UNIT_TESTS
	if (const auto checker = ExternalPathCheckerForTesting()) {
		return (*checker)(operation, path, callsite);
	}
#endif // TDESKTOP_UNIT_TESTS
	return CheckExternalPath(operation, path, callsite);
}

[[nodiscard]] inline std::optional<QString>
LocalFilePathFromUrl(const QString &url) {
	const auto parsed = QUrl(url);
	return parsed.isLocalFile() ? std::make_optional(parsed.toLocalFile())
								: std::nullopt;
}

template <typename Dispatch>
[[nodiscard]] bool
DispatchExternalPathIfAllowed(Operation operation, const QString &path,
							  const char *callsite, Dispatch &&dispatch) {
	if (!CheckExternalPathForUse(operation, path, callsite)) {
		return false;
	}
	std::forward<Dispatch>(dispatch)();
	return true;
}

template <typename Dispatch>
[[nodiscard]] bool DispatchCustomAppIconIfAllowed(const QString &source,
												  const char *callsite,
												  Dispatch &&dispatch) {
	const auto check = [&](Operation operation, const QString &path) {
		return CheckExternalPathForUse(operation, path, callsite);
	};
	if (!source.isEmpty() && !check(Operation::Read, source)) {
		return false;
	}
	const auto bundle
		= QDir::cleanPath(QCoreApplication::applicationDirPath() + u"/../.."_q);
	const auto icon = bundle + u"/Icon\r"_q;
	const auto temporary = QDir::tempPath();
	if (!check(Operation::Read, bundle) || !check(Operation::Write, bundle)
		|| !check(Operation::Read, icon) || !check(Operation::Write, icon)
		|| !check(Operation::OpenDir, temporary)
		|| !check(Operation::Write, temporary)) {
		return false;
	}
	std::forward<Dispatch>(dispatch)();
	return true;
}

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
				return CheckExternalPathForUse(checkedOperation, checkedPath,
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
			return CheckExternalPathForUse(checkedOperation, checkedPath,
										   checkedCallsite);
		});
}

template <typename Checker>
[[nodiscard]] bool RemoveExternalFile(QFile &file, const char *callsite,
									  Checker &&checker) {
	const auto path = file.fileName();
	return !path.isEmpty()
		   && PersistedExternalPath(path).allowed(
			   Operation::Unlink, callsite, std::forward<Checker>(checker))
		   && file.remove();
}

[[nodiscard]] inline bool RemoveExternalFile(QFile &file,
											 const char *callsite) {
	return RemoveExternalFile(
		file, callsite,
		[](Operation checkedOperation, const QString &checkedPath,
		   const char *checkedCallsite) {
			return CheckExternalPathForUse(checkedOperation, checkedPath,
										   checkedCallsite);
		});
}

} // namespace Core::MacProtectedPath
