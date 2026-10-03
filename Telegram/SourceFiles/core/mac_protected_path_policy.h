/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QMutex>
#include <QtCore/QString>

#include <functional>
#include <map>
#include <utility>
#include <vector>

namespace Core::MacProtectedPath {

enum class Operation {
	Open,
	Read,
	Write,
	Stat,
	Lstat,
	OpenDir,
	GetAttrList,
	Mkdir,
	Lock,
	Rename,
	Copy,
	Link,
	Unlink,
	Rmdir,
	RecursiveDelete,
};

enum class ProtectedClass {
	None,
	ApplicationSupport,
	Container,
	GroupContainer,
	BundleKeyed,
	Invalid,
};

enum class FileType {
	Directory,
	Regular,
	Symlink,
	Other,
};

enum class FileError {
	None,
	Missing,
	NotDirectory,
	Loop,
	Unexpected,
	Ambiguous,
};

struct LstatResult {
	FileType type = FileType::Other;
	FileError error = FileError::Unexpected;
};

struct ReadlinkResult {
	QByteArray target;
	FileError error = FileError::Unexpected;
};

struct FileSystem {
	std::function<LstatResult(const QByteArray &)> lstat;
	std::function<ReadlinkResult(const QByteArray &)> readlink;
	std::function<void(const QByteArray &)> open;
};

struct HomeRoots {
	QByteArray accountDatabase;
	QByteArray environment;
	QByteArray foundation;
};

[[nodiscard]] QByteArray TeagramProfileRoot(const HomeRoots &homes,
											bool appSandboxed);

struct RefusalRecord {
	Operation operation = Operation::Open;
	ProtectedClass protectedClass = ProtectedClass::Invalid;
	QString callsite;
};

class RefusalLog final {
public:
	explicit RefusalLog(std::function<qint64()> clock = {});

	[[nodiscard]] bool record(const RefusalRecord &refusal);

	[[nodiscard]] const std::vector<RefusalRecord> &records() const;

private:
  QMutex _mutex;
  std::function<qint64()> _clock;
  std::map<std::pair<int, int>, qint64> _last;
  std::vector<RefusalRecord> _records;
};

enum class ResolutionStatus {
	Allowed,
	Refused,
};

struct Resolution {
	ResolutionStatus status = ResolutionStatus::Refused;
	QByteArray resolvedPath;
	RefusalRecord refusal;

	[[nodiscard]] bool allowed() const;
};

struct PairResolution {
	Resolution first;
	Resolution second;

	[[nodiscard]] bool allowed() const;
};

class MacProtectedPathPolicy final {
public:
	using Components = std::vector<QString>;

	[[nodiscard]] static MacProtectedPathPolicy
	Build(const HomeRoots &homes, const FileSystem &filesystem,
		  RefusalRecord *failure = nullptr);

	[[nodiscard]] bool valid() const;

	[[nodiscard]] ProtectedClass Classify(
		const QByteArray &absolutePath) const;

	[[nodiscard]] Resolution Resolve(
		Operation operation,
		const QByteArray &path,
		const QByteArray &anchor,
		const QString &callsite,
		RefusalLog *refusals = nullptr) const;

	[[nodiscard]] PairResolution ResolvePair(
		Operation operation,
		const QByteArray &first,
		const QByteArray &second,
		const QByteArray &anchor,
		const QString &callsite,
		RefusalLog *refusals = nullptr) const;

private:
	MacProtectedPathPolicy() = default;

	[[nodiscard]] Resolution ResolveBytes(
		Operation operation,
		const QByteArray &path,
		const QByteArray &anchor,
		const QString &callsite,
		RefusalLog *refusals) const;

	[[nodiscard]] ProtectedClass ClassifyComponents(
		const Components &components) const;
	[[nodiscard]] ProtectedClass ClassifyAncestorComponents(
		const Components &components) const;

	[[nodiscard]] bool IsHomeRoot(const Components &components) const;

	bool _valid = false;
	FileSystem _filesystem;
	std::vector<Components> _homeRoots;

};

} // namespace Core::MacProtectedPath
