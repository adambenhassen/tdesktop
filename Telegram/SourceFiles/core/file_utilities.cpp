/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/file_utilities.h"

#include "core/mac_protected_path_runtime.h"
#include "core/version.h"
#include "storage/localstorage.h"
#include "storage/storage_account.h"
#include "base/platform/base_platform_file_utilities.h"
#include "platform/platform_file_utilities.h"
#include "core/application.h"
#include "base/unixtime.h"
#include "ui/delayed_activation.h"
#include "ui/chat/attach/attach_extensions.h"
#include "main/main_session.h"
#include "mainwindow.h"

#include <QtWidgets/QFileDialog>
#include <QtCore/QCoreApplication>
#include <QtCore/QStandardPaths>
#include <QtGui/QDesktopServices>

bool filedialogGetSaveFile(
		QPointer<QWidget> parent,
		QString &file,
		const QString &caption,
		const QString &filter,
		const QString &initialPath) {
	QStringList files;
	QByteArray remoteContent;
	Ui::PreventDelayedActivation();
	bool result = Platform::FileDialog::Get(
		parent,
		files,
		remoteContent,
		caption,
		filter,
		FileDialog::internal::Type::WriteFile,
		initialPath);
	const auto selected = files.isEmpty() ? QString() : files.at(0);
	if (!selected.isEmpty()
		&& !Core::MacProtectedPath::CheckExternalPath(
			Core::MacProtectedPath::Operation::Write, selected,
			"file-dialog.write-result")) {
		file.clear();
		return false;
	}
	file = selected;
	return result;
}

bool filedialogGetSaveFile(
		QString &file,
		const QString &caption,
		const QString &filter,
		const QString &initialPath) {
	return filedialogGetSaveFile(
		Core::App().getFileDialogParent(),
		file,
		caption,
		filter,
		initialPath);
}

QString filedialogDefaultName(
		const QString &prefix,
		const QString &extension,
		const QString &path,
		bool skipExistance,
		TimeId fileTime) {
	auto directoryPath = path;
	if (directoryPath.isEmpty()) {
		if (cDialogLastPath().isEmpty()) {
			Platform::FileDialog::InitLastPath();
		}
		directoryPath = cDialogLastPath();
	}
	if (!directoryPath.isEmpty()
		&& !Core::MacProtectedPath::CheckExternalPath(
			Core::MacProtectedPath::Operation::OpenDir, directoryPath,
			"file-dialog.default-name-directory")) {
		return QString();
	}

	QString base;
	if (fileTime) {
		const auto date = base::unixtime::parse(fileTime);
		base = prefix + date.toString("_yyyy-MM-dd_HH-mm-ss");
	} else {
		struct tm tm;
		time_t t = time(NULL);
		mylocaltime(&tm, &t);

		const auto zero = QChar('0');
		base = prefix + u"_%1-%2-%3_%4-%5-%6"_q.arg(tm.tm_year + 1900).arg(tm.tm_mon + 1, 2, 10, zero).arg(tm.tm_mday, 2, 10, zero).arg(tm.tm_hour, 2, 10, zero).arg(tm.tm_min, 2, 10, zero).arg(tm.tm_sec, 2, 10, zero);
	}

	QString name;
	if (skipExistance) {
		name = base + extension;
	} else {
		QDir directory(directoryPath);
		const auto dir = directory.absolutePath();
		const auto nameBase = (dir.endsWith('/') ? dir : (dir + '/'))
			+ base;
		name = nameBase + extension;
		for (int i = 0; Core::MacProtectedPath::CheckExternalPath(
							Core::MacProtectedPath::Operation::Stat, name,
							"file-dialog.default-name-stat")
						&& QFileInfo::exists(name);
			 ++i) {
			name = nameBase + u" (%1)"_q.arg(i + 2) + extension;
		}
		if (!Core::MacProtectedPath::CheckExternalPath(
				Core::MacProtectedPath::Operation::Write, name,
				"file-dialog.default-name-write")) {
			return QString();
		}
	}
	return name;
}

QString filedialogNextFilename(
		const QString &name,
		const QString &cur,
		const QString &path) {
	const auto directoryPath = path.isEmpty() ? cDialogLastPath() : path;
	if (!directoryPath.isEmpty()
		&& !Core::MacProtectedPath::CheckExternalPath(
			Core::MacProtectedPath::Operation::OpenDir, directoryPath,
			"file-dialog.next-filename-directory")) {
		return QString();
	}
	QDir directory(directoryPath);
	int32 extIndex = name.lastIndexOf('.');
	QString prefix = name, extension;
	if (extIndex >= 0) {
		extension = name.mid(extIndex);
		prefix = name.mid(0, extIndex);
	}
	const auto dir = directory.absolutePath();
	const auto nameBase = (dir.endsWith('/') ? dir : (dir + '/')) + prefix;
	auto result = nameBase + extension;
	for (int i = 0; result.toLower() != cur.toLower()
					&& Core::MacProtectedPath::CheckExternalPath(
						Core::MacProtectedPath::Operation::Stat, result,
						"file-dialog.next-filename-stat")
					&& QFileInfo::exists(result);
		 ++i) {
		result = nameBase + u" (%1)"_q.arg(i + 2) + extension;
	}
	return Core::MacProtectedPath::CheckExternalPath(
			   Core::MacProtectedPath::Operation::Write, result,
			   "file-dialog.next-filename-write")
			   ? result
			   : QString();
}

namespace File {

void OpenUrl(const QString &url) {
	crl::on_main([=] {
		Ui::PreventDelayedActivation();
		Platform::File::UnsafeOpenUrl(url);
	});
}

void OpenEmailLink(const QString &email) {
	crl::on_main([=] {
		Ui::PreventDelayedActivation();
		Platform::File::UnsafeOpenEmailLink(email);
	});
}

void OpenWith(const QString &filepath) {
	InvokeQueued(QCoreApplication::instance(), [=] {
		if (!Platform::File::UnsafeShowOpenWithDropdown(filepath)) {
			Ui::PreventDelayedActivation();
			if (!Platform::File::UnsafeShowOpenWith(filepath)) {
				Platform::File::UnsafeLaunch(filepath);
			}
		}
	});
}

void Launch(const QString &filepath) {
	crl::on_main([=] {
		Ui::PreventDelayedActivation();
		Platform::File::UnsafeLaunch(filepath);
	});
}

void ShowInFolder(const QString &filepath) {
	crl::on_main([=] {
		Ui::PreventDelayedActivation();
		base::Platform::ShowInFolder(filepath);
	});
}

QString DefaultDownloadPathFolder(not_null<Main::Session*> session) {
#if OS_MAC_STORE
	return u"Telegram Lite"_q;
#else // OS_MAC_STORE
	return session->supportMode() ? u"Tsupport Desktop"_q : AppName.utf16();
#endif // OS_MAC_STORE
}

QString DefaultDownloadPath(not_null<Main::Session*> session) {
	if (!Core::App().canReadDefaultDownloadPath()) {
		return session->local().tempDirectory();
	}
	return QStandardPaths::writableLocation(
		QStandardPaths::DownloadLocation)
		+ '/'
		+ DefaultDownloadPathFolder(session)
		+ '/';
}

namespace internal {

void UnsafeOpenUrlDefault(const QString &url) {
	QDesktopServices::openUrl(url);
}

void UnsafeOpenEmailLinkDefault(const QString &email) {
	auto url = QUrl(u"mailto:"_q + email);
	QDesktopServices::openUrl(url);
}

void UnsafeLaunchDefault(const QString &filepath) {
	QDesktopServices::openUrl(QUrl::fromLocalFile(filepath));
}

} // namespace internal
} // namespace File

namespace FileDialog {

void GetOpenPath(
		QPointer<QWidget> parent,
		const QString &caption,
		const QString &filter,
		Fn<void(OpenResult &&result)> callback,
		Fn<void()> failed) {
	InvokeQueued(QCoreApplication::instance(), [=] {
		auto files = QStringList();
		auto remoteContent = QByteArray();
		Ui::PreventDelayedActivation();
		const auto success = Platform::FileDialog::Get(
			parent,
			files,
			remoteContent,
			caption,
			filter,
			FileDialog::internal::Type::ReadFile);
		const auto pathsAllowed
			= ranges::all_of(files, [](const QString &path) {
				  return Core::MacProtectedPath::CheckExternalPath(
					  Core::MacProtectedPath::Operation::Read, path,
					  "file-dialog.open-result");
			  });
		if (success && pathsAllowed
			&& ((!files.isEmpty() && !files[0].isEmpty())
				|| !remoteContent.isEmpty())) {
			if (callback) {
				auto result = OpenResult();
				if (!files.isEmpty() && !files[0].isEmpty()) {
					result.paths.push_back(files[0]);
				}
				result.remoteContent = remoteContent;
				callback(std::move(result));
			}
		} else if (failed) {
			failed();
		}
	});
}

void GetOpenPaths(
		QPointer<QWidget> parent,
		const QString &caption,
		const QString &filter,
		Fn<void(OpenResult &&result)> callback,
		Fn<void()> failed) {
	InvokeQueued(QCoreApplication::instance(), [=] {
		auto files = QStringList();
		auto remoteContent = QByteArray();
		Ui::PreventDelayedActivation();
		const auto success = Platform::FileDialog::Get(
			parent,
			files,
			remoteContent,
			caption,
			filter,
			FileDialog::internal::Type::ReadFiles);
		const auto pathsAllowed
			= ranges::all_of(files, [](const QString &path) {
				  return Core::MacProtectedPath::CheckExternalPath(
					  Core::MacProtectedPath::Operation::Read, path,
					  "file-dialog.open-results");
			  });
		if (success && pathsAllowed
			&& (!files.isEmpty() || !remoteContent.isEmpty())) {
			if (callback) {
				auto result = OpenResult();
				result.paths = files;
				result.remoteContent = remoteContent;
				callback(std::move(result));
			}
		} else if (failed) {
			failed();
		}
	});
}

void GetWritePath(
		QPointer<QWidget> parent,
		const QString &caption,
		const QString &filter,
		const QString &initialPath,
		Fn<void(QString &&result)> callback,
		Fn<void()> failed) {
	InvokeQueued(QCoreApplication::instance(), [=] {
		auto file = QString();
		if (filedialogGetSaveFile(parent, file, caption, filter, initialPath)) {
			const auto allowed = Core::MacProtectedPath::CheckExternalPath(
				Core::MacProtectedPath::Operation::Write, file,
				"file-dialog.write-result");
			if (allowed && callback) {
				callback(std::move(file));
			} else if (!allowed && failed) {
				failed();
			}
		} else if (failed) {
			failed();
		}
	});
}

void GetFolder(
		QPointer<QWidget> parent,
		const QString &caption,
		const QString &initialPath,
		Fn<void(QString &&result)> callback,
		Fn<void()> failed) {
	InvokeQueued(QCoreApplication::instance(), [=] {
		auto files = QStringList();
		auto remoteContent = QByteArray();
		Ui::PreventDelayedActivation();
		const auto success = Platform::FileDialog::Get(
			parent,
			files,
			remoteContent,
			caption,
			QString(),
			FileDialog::internal::Type::ReadFolder,
			initialPath);
		if (success && !files.isEmpty() && !files[0].isEmpty()
			&& Core::MacProtectedPath::CheckExternalPath(
				Core::MacProtectedPath::Operation::OpenDir, files[0],
				"file-dialog.folder-result")) {
			if (callback) {
				callback(std::move(files[0]));
			}
		} else if (failed) {
			failed();
		}
	});
}

QString AllFilesFilter() {
#ifdef Q_OS_WIN
	return u"All files (*.*)"_q;
#else // Q_OS_WIN
	return u"All files (*)"_q;
#endif // Q_OS_WIN
}

QString ImagesFilter() {
	return u"Image files (*"_q + Ui::ImageExtensions().join(u" *"_q) + u")"_q;
}

QString AllOrImagesFilter() {
	return AllFilesFilter() + u";;"_q + ImagesFilter();
}

QString ImagesOrAllFilter() {
	return ImagesFilter() + u";;"_q + AllFilesFilter();
}

QString PhotoVideoFilesFilter() {
	return u"Image and Video Files (*"_q
		+ Ui::ImageExtensions().join(u" *"_q)
		+ u" *.mp4 *.mov *.m4v);;"_q
		+ AllFilesFilter();
}

QString PhotoVideoAudioFilesFilter() {
	return u"Image, Video and Audio Files (*"_q
		+ Ui::ImageExtensions().join(u" *"_q)
		+ u" *.mp4 *.mov *.m4v *.webm"_q
		+ u" *.mp3 *.m4a *.aac *.ogg *.flac *.opus *.oga)"_q;
}

QString AudioFilesFilter() {
	return u"Audio Files (*.mp3 *.m4a *.aac *.ogg *.flac *.opus *.oga);;"_q
		+ AllFilesFilter();
}

const QString &Tmp() {
	static const auto tmp = u"tmp"_q;
	return tmp;
}

namespace internal {

void InitLastPathDefault() {
	const auto path
		= QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
	if (Core::MacProtectedPath::CheckExternalPath(
			Core::MacProtectedPath::Operation::OpenDir, path,
			"file-dialog.default-path")) {
		cSetDialogLastPath(path);
	}
}

bool GetDefault(
		QPointer<QWidget> parent,
		QStringList &files,
		QByteArray &remoteContent,
		const QString &caption,
		const QString &filter,
		FileDialog::internal::Type type,
		QString startFile = QString()) {
	if (cDialogLastPath().isEmpty()) {
		Platform::FileDialog::InitLastPath();
	}

	remoteContent = QByteArray();
	const auto lastPath = cDialogLastPath();
	const auto lastPathAllowed = lastPath.isEmpty()
								 || Core::MacProtectedPath::CheckExternalPath(
									 Core::MacProtectedPath::Operation::OpenDir,
									 lastPath, "file-dialog.last-path");
	if (!lastPathAllowed && (startFile.isEmpty() || startFile.at(0) != '/')) {
		startFile.clear();
	} else if ((startFile.isEmpty() || startFile.at(0) != '/')
			   && (!lastPath.isEmpty()
				   || !Core::MacProtectedPath::IntegrationTestActive())) {
		startFile = lastPath + '/' + startFile;
	}
	if (!startFile.isEmpty()
		&& !Core::MacProtectedPath::CheckExternalPath(
			Core::MacProtectedPath::Operation::Open, startFile,
			"file-dialog.initial-path")) {
		startFile.clear();
	}
	QString file;

	const auto resolvedParent = (parent && parent->window()->isVisible())
		? parent->window()
		: Core::App().getFileDialogParent();
	Core::App().notifyFileDialogShown(true);
	const auto guard = gsl::finally([] {
		Core::App().notifyFileDialogShown(false);
	});
	if (type == Type::ReadFiles) {
		files = QFileDialog::getOpenFileNames(resolvedParent, caption, startFile, filter);
		const auto pathsAllowed
			= ranges::all_of(files, [](const QString &path) {
				  return Core::MacProtectedPath::CheckExternalPath(
					  Core::MacProtectedPath::Operation::Read, path,
					  "file-dialog.selected-path");
			  });
		if (!pathsAllowed) {
			files.clear();
			return false;
		}
		QString path = files.isEmpty() ? QString() : QFileInfo(files.back()).absoluteDir().absolutePath();
		if (!path.isEmpty()
			&& Core::MacProtectedPath::CheckExternalPath(
				Core::MacProtectedPath::Operation::OpenDir, path,
				"file-dialog.selected-directory")
			&& path != cDialogLastPath()) {
			cSetDialogLastPath(path);
			Local::writeSettings();
		}
		return !files.isEmpty();
	} else if (type == Type::ReadFolder) {
		file = QFileDialog::getExistingDirectory(resolvedParent, caption, startFile);
	} else if (type == Type::WriteFile) {
		file = QFileDialog::getSaveFileName(resolvedParent, caption, startFile, filter);
	} else {
		file = QFileDialog::getOpenFileName(resolvedParent, caption, startFile, filter);
	}

	if (file.isEmpty()) {
		files = QStringList();
		return false;
	}
	const auto selectedOperation
		= (type == Type::WriteFile) ? Core::MacProtectedPath::Operation::Write
		  : (type == Type::ReadFolder)
			  ? Core::MacProtectedPath::Operation::OpenDir
			  : Core::MacProtectedPath::Operation::Read;
	if (!Core::MacProtectedPath::CheckExternalPath(
			selectedOperation, file, "file-dialog.selected-path")) {
		files.clear();
		return false;
	}
	if (type != Type::ReadFolder) {
		// Save last used directory for all queries except directory choosing.
		auto path = QFileInfo(file).absoluteDir().absolutePath();
		if (!path.isEmpty()
			&& Core::MacProtectedPath::CheckExternalPath(
				Core::MacProtectedPath::Operation::OpenDir, path,
				"file-dialog.selected-directory")
			&& path != cDialogLastPath()) {
			cSetDialogLastPath(path);
			Local::writeSettings();
		}
	}
	files = QStringList(file);
	return true;
}

} // namespace internal
} // namespace FileDialog
