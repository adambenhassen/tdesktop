/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/mac_protected_path_policy.h"

#include <QtCore/QDateTime>
#include <QtCore/QMutexLocker>

#include <algorithm>
#include <deque>
#include <initializer_list>
#include <utility>

namespace Core::MacProtectedPath {
namespace {

constexpr auto kSymlinkHopLimit = 32;
constexpr auto kRefusalInterval = qint64(60);

struct ParsedPath {
	bool absolute = false;
	std::vector<QByteArray> components;
};

struct WalkResult {
	enum class Status {
	Allowed,
	Refused,
	Invalid,
	};

	Status status = Status::Invalid;
	std::vector<QByteArray> components;
	ProtectedClass protectedClass = ProtectedClass::Invalid;
	FileType finalType = FileType::Other;
};

[[nodiscard]] bool IsContinuation(uchar value) {
	return value >= 0x80 && value <= 0xBF;
}

[[nodiscard]] bool IsValidUtf8(const QByteArray &value) {
	for (auto i = 0; i < value.size();) {
		const auto first = uchar(value.at(i));
		if (first <= 0x7F) {
			++i;
			continue;
		}
		if (first >= 0xC2 && first <= 0xDF) {
			if (i + 1 >= value.size()
				|| !IsContinuation(uchar(value.at(i + 1)))) {
				return false;
			}
			i += 2;
			continue;
		}
		if (first == 0xE0) {
			if (i + 2 >= value.size()
				|| uchar(value.at(i + 1)) < 0xA0
				|| uchar(value.at(i + 1)) > 0xBF
				|| !IsContinuation(uchar(value.at(i + 2)))) {
				return false;
			}
			i += 3;
			continue;
		}
		if (first >= 0xE1 && first <= 0xEC) {
			if (i + 2 >= value.size()
				|| !IsContinuation(uchar(value.at(i + 1)))
				|| !IsContinuation(uchar(value.at(i + 2)))) {
				return false;
			}
			i += 3;
			continue;
		}
		if (first == 0xED) {
			if (i + 2 >= value.size()
				|| uchar(value.at(i + 1)) < 0x80
				|| uchar(value.at(i + 1)) > 0x9F
				|| !IsContinuation(uchar(value.at(i + 2)))) {
				return false;
			}
			i += 3;
			continue;
		}
		if (first >= 0xEE && first <= 0xEF) {
			if (i + 2 >= value.size()
				|| !IsContinuation(uchar(value.at(i + 1)))
				|| !IsContinuation(uchar(value.at(i + 2)))) {
				return false;
			}
			i += 3;
			continue;
		}
		if (first == 0xF0) {
			if (i + 3 >= value.size()
				|| uchar(value.at(i + 1)) < 0x90
				|| uchar(value.at(i + 1)) > 0xBF
				|| !IsContinuation(uchar(value.at(i + 2)))
				|| !IsContinuation(uchar(value.at(i + 3)))) {
				return false;
			}
			i += 4;
			continue;
		}
		if (first >= 0xF1 && first <= 0xF3) {
			if (i + 3 >= value.size()
				|| !IsContinuation(uchar(value.at(i + 1)))
				|| !IsContinuation(uchar(value.at(i + 2)))
				|| !IsContinuation(uchar(value.at(i + 3)))) {
				return false;
			}
			i += 4;
			continue;
		}
		if (first == 0xF4) {
			if (i + 3 >= value.size()
				|| uchar(value.at(i + 1)) < 0x80
				|| uchar(value.at(i + 1)) > 0x8F
				|| !IsContinuation(uchar(value.at(i + 2)))
				|| !IsContinuation(uchar(value.at(i + 3)))) {
				return false;
			}
			i += 4;
			continue;
		}
		return false;
	}
	return !value.contains('\0');
}

[[nodiscard]] QString Fold(const QByteArray &component) {
	auto result = QString::fromUtf8(component);
	result = result.normalized(QString::NormalizationForm_D).toCaseFolded();
	for (auto i = result.size() - 1; i >= 0; --i) {
		const auto codepoint = result.at(i).unicode();
		if ((codepoint >= 0x200B && codepoint <= 0x200F)
			|| (codepoint >= 0x202A && codepoint <= 0x202E)
			|| (codepoint >= 0x206A && codepoint <= 0x206F)
			|| codepoint == 0xFEFF) {
			result.remove(i, 1);
		}
	}
	return result;
}

[[nodiscard]] bool ParseComponent(
		const QByteArray &value) {
	if (value.isEmpty() || !IsValidUtf8(value)) {
		return false;
	}
	return !Fold(value).isEmpty();
}

[[nodiscard]] bool ParsePath(
		const QByteArray &value,
		ParsedPath *result) {
	if (!result || value.isEmpty() || !IsValidUtf8(value)) {
		return false;
	}
	result->absolute = value.startsWith('/');
	result->components.clear();
	const auto parts = value.split('/');
	for (const auto &part : parts) {
		if (part.isEmpty()) {
			continue;
		}
		if (!ParseComponent(part)) {
			return false;
		}
		result->components.push_back(part);
	}
	return true;
}

[[nodiscard]] QByteArray Join(
		const std::vector<QByteArray> &components) {
	auto result = QByteArray("/");
	for (const auto &component : components) {
		if (result.size() > 1) {
			result.append('/');
		}
		result.append(component);
	}
	return result;
}

[[nodiscard]] MacProtectedPathPolicy::Components FoldedComponents(
		const std::vector<QByteArray> &components) {
	MacProtectedPathPolicy::Components result;
	result.reserve(components.size());
	for (const auto &component : components) {
		result.push_back(Fold(component));
	}
	return result;
}

[[nodiscard]] bool StartsWith(
		const MacProtectedPathPolicy::Components &value,
		const MacProtectedPathPolicy::Components &prefix) {
	if (value.size() < prefix.size()) {
		return false;
	}
	return std::equal(prefix.begin(), prefix.end(), value.begin());
}

[[nodiscard]] bool SameComponents(
		const MacProtectedPathPolicy::Components &left,
		const MacProtectedPathPolicy::Components &right) {
	return left == right;
}

[[nodiscard]] bool IsDestructive(Operation operation) {
	return operation == Operation::Rename
		|| operation == Operation::Link
		|| operation == Operation::Unlink
		|| operation == Operation::Rmdir
		|| operation == Operation::RecursiveDelete;
}

[[nodiscard]] bool FollowsFinalComponent(Operation operation) {
	return operation != Operation::Lstat && operation != Operation::Mkdir
		   && operation != Operation::Link && operation != Operation::Rename
		   && operation != Operation::Unlink && operation != Operation::Rmdir;
}

[[nodiscard]] MacProtectedPathPolicy::Components ComponentsFromAscii(
		std::initializer_list<const char *> values) {
	MacProtectedPathPolicy::Components result;
	for (const auto value : values) {
		result.push_back(Fold(QByteArray(value)));
	}
	return result;
}

[[nodiscard]] std::vector<QByteArray> CanonicalRawComponents(
		const std::vector<QByteArray> &components) {
	std::vector<QByteArray> result;
	for (const auto &component : components) {
		if (component == ".") {
			continue;
		}
		if (component == "..") {
			if (!result.empty()) {
				result.pop_back();
			}
			continue;
		}
		result.push_back(component);
	}
	return result;
}

[[nodiscard]] std::vector<QByteArray> FirmlinkAlias(
		const std::vector<QByteArray> &components) {
	const auto folded = FoldedComponents(components);
	const auto data = ComponentsFromAscii({ "system", "volumes", "data" });
	if (StartsWith(folded, data)) {
		return std::vector<QByteArray>(
			components.begin() + data.size(),
			components.end());
	}
	auto result = std::vector<QByteArray>{
		"System", "Volumes", "Data" };
	result.insert(result.end(), components.begin(), components.end());
	return result;
}

template <typename Classify, typename ClassifySymlinkTarget, typename IsHome>
[[nodiscard]] WalkResult
Walk(const ParsedPath &path, const FileSystem &filesystem, Classify &&classify,
	 ClassifySymlinkTarget &&classifySymlinkTarget, IsHome &&isHome,
	 bool allowMissingSuffix, bool followFinalComponent) {
	if (!path.absolute || !filesystem.lstat || !filesystem.readlink) {
		return {};
	}

	auto pending = std::deque<QByteArray>(
		path.components.begin(),
		path.components.end());
	std::vector<QByteArray> resolved;
	std::vector<FileType> resolvedTypes;
	auto missingSuffix = false;
	auto symlinkHops = 0;

	while (!pending.empty()) {
		auto component = std::move(pending.front());
		pending.pop_front();

		if (component == ".") {
			continue;
		}
		if (component == "..") {
			if (missingSuffix) {
				return {};
			}
			if (!resolved.empty()) {
				if (resolvedTypes.back() != FileType::Directory) {
					return {};
				}
				resolved.pop_back();
				resolvedTypes.pop_back();
			}
			continue;
		}

		resolved.push_back(component);
		const auto components = FoldedComponents(resolved);
		const auto protectedClass = classify(components, pending.empty());
		if (protectedClass != ProtectedClass::None) {
			return {
				.status = WalkResult::Status::Refused,
				.components = std::move(resolved),
				.protectedClass = protectedClass };
		}
		if (pending.empty() && !followFinalComponent) {
			resolvedTypes.push_back(FileType::Other);
			break;
		}

		if (missingSuffix) {
			resolvedTypes.push_back(FileType::Other);
			continue;
		}

		const auto pathBytes = Join(resolved);
		const auto lstat = filesystem.lstat(pathBytes);
		if (lstat.error == FileError::Missing) {
			if (isHome(components)) {
				return {};
			}
			if (!allowMissingSuffix) {
				return {};
			}
			missingSuffix = true;
			resolvedTypes.push_back(FileType::Other);
			continue;
		}
		if (lstat.error != FileError::None) {
			return {};
		}
		if (lstat.type == FileType::Symlink) {
			if (++symlinkHops > kSymlinkHopLimit) {
				return {};
			}
			const auto readlink = filesystem.readlink(pathBytes);
			if (readlink.error != FileError::None) {
				return {};
			}
			ParsedPath target;
			if (!ParsePath(readlink.target, &target)) {
				return {};
			}
			auto targetComponents
				= target.absolute ? std::vector<QByteArray>()
								  : std::vector<QByteArray>(resolved.begin(),
															resolved.end() - 1);
			targetComponents.insert(targetComponents.end(),
									target.components.begin(),
									target.components.end());
			const auto targetClass = classifySymlinkTarget(
				FoldedComponents(CanonicalRawComponents(targetComponents)));
			if (targetClass != ProtectedClass::None) {
				return {.status = WalkResult::Status::Refused,
						.components = std::move(resolved),
						.protectedClass = targetClass};
			}
			resolved.pop_back();
			if (target.absolute) {
				resolved.clear();
				resolvedTypes.clear();
			}
			for (auto i = target.components.rbegin();
				i != target.components.rend();
				++i) {
				pending.push_front(*i);
			}
			continue;
		}
		resolvedTypes.push_back(lstat.type);
		if (!pending.empty() && lstat.type != FileType::Directory) {
			return {};
		}
	}

	const auto protectedClass = classify(FoldedComponents(resolved), true);
	if (protectedClass != ProtectedClass::None) {
		return {
			.status = WalkResult::Status::Refused,
			.components = std::move(resolved),
			.protectedClass = protectedClass };
	}

	return {
		.status = WalkResult::Status::Allowed,
		.components = std::move(resolved),
		.protectedClass = ProtectedClass::None,
		.finalType = resolvedTypes.empty()
			? FileType::Directory
			: resolvedTypes.back() };
}

[[nodiscard]] Resolution Refused(
		Operation operation,
		ProtectedClass protectedClass,
		const QString &callsite,
		RefusalLog *refusals) {
	const auto refusal = RefusalRecord{ operation, protectedClass, callsite };
	if (refusals) {
		static_cast<void>(refusals->record(refusal));
	}
	return {
		.status = ResolutionStatus::Refused,
		.refusal = refusal };
}

[[nodiscard]] Resolution Allowed(const std::vector<QByteArray> &components) {
	return {
		.status = ResolutionStatus::Allowed,
		.resolvedPath = Join(components) };
}

[[nodiscard]] bool IsAbsoluteHome(const ParsedPath &path) {
	return path.absolute && !path.components.empty();
}

} // namespace

RefusalLog::RefusalLog(std::function<qint64()> clock)
: _clock(clock ? std::move(clock) : [] {
	return QDateTime::currentSecsSinceEpoch();
}) {
}

bool RefusalLog::record(const RefusalRecord &refusal) {
	QMutexLocker lock(&_mutex);
	const auto key = std::pair(
		int(refusal.operation),
		int(refusal.protectedClass));
	const auto now = _clock();
	const auto i = _last.find(key);
	if (i != _last.end()
		&& (now < i->second || now - i->second < kRefusalInterval)) {
		return false;
	}
	_last[key] = now;
	_records.push_back(refusal);
	return true;
}

const std::vector<RefusalRecord> &RefusalLog::records() const {
	return _records;
}

bool Resolution::allowed() const {
	return status == ResolutionStatus::Allowed;
}

bool PairResolution::allowed() const {
	return first.allowed() && second.allowed();
}

QByteArray TeagramProfileRoot(const HomeRoots &homes, bool appSandboxed) {
	auto result = appSandboxed ? homes.foundation : homes.accountDatabase;
	if (result.isEmpty()) {
		return {};
	}
	while (result.size() > 1 && result.endsWith('/')) {
		result.chop(1);
	}
	if (!result.endsWith('/')) {
		result.append('/');
	}
	result.append("Library/Application Support/Teagram");
	return result;
}

MacProtectedPathPolicy
MacProtectedPathPolicy::Build(const HomeRoots &homes,
							  const FileSystem &filesystem,
							  RefusalRecord *failure) {
	auto result = MacProtectedPathPolicy();
	if (failure) {
		*failure = {.operation = Operation::Open,
					.protectedClass = ProtectedClass::Invalid,
					.callsite = u"profile.home"_q};
	}
	if (homes.accountDatabase.isEmpty()
		|| homes.foundation.isEmpty()) {
		return result;
	}
	result._filesystem = filesystem;

	const auto values = std::vector<QByteArray>{
		homes.accountDatabase,
		homes.environment,
		homes.foundation };
	struct HomeCandidate {
		std::vector<QByteArray> traversal;
		std::vector<QByteArray> raw;
		Components folded;
	};
	auto candidates = std::vector<HomeCandidate>();
	auto preflightHomes = std::vector<Components>();
	const auto library = Fold(QByteArray("Library"));
	const auto addHomeRoot = [](
			std::vector<Components> &roots,
			Components root) {
		if (root.empty()) {
			return;
		}
		if (std::none_of(
				roots.begin(),
				roots.end(),
				[&](const auto &existing) {
					return SameComponents(existing, root);
				})) {
				roots.push_back(std::move(root));
			}
		};
	// A home beneath Library needs the prefix before Library for classification.
	// Seed every candidate before the first filesystem probe.
	const auto addHomeCandidates = [&](
			const std::vector<QByteArray> &raw,
			std::vector<Components> &roots) {
		addHomeRoot(roots, FoldedComponents(raw));
		addHomeRoot(roots, FoldedComponents(FirmlinkAlias(raw)));
		for (auto i = 1; i < int(raw.size()); ++i) {
			if (Fold(raw[i]) != library) {
				continue;
			}
			const auto prefix = std::vector<QByteArray>(
				raw.begin(),
				raw.begin() + i);
			addHomeRoot(roots, FoldedComponents(prefix));
			addHomeRoot(roots, FoldedComponents(FirmlinkAlias(prefix)));
		}
	};
	for (const auto &value : values) {
		if (value.isEmpty()) {
			continue;
		}
		ParsedPath parsed;
		if (!ParsePath(value, &parsed) || !IsAbsoluteHome(parsed)) {
			return result;
		}
		auto traversal = std::move(parsed.components);
		auto raw = CanonicalRawComponents(traversal);
		auto folded = FoldedComponents(raw);
		if (folded.empty()) {
			return result;
		}
		addHomeCandidates(raw, preflightHomes);
		candidates.push_back({
			std::move(traversal),
			std::move(raw),
			std::move(folded) });
	}
	if (candidates.empty()) {
		return result;
	}
	auto classifier = MacProtectedPathPolicy();
	classifier._valid = true;
	const auto classify = [&](const Components &components, bool) {
		classifier._homeRoots = preflightHomes;
		// A symlink can reveal a home only as traversal reaches it.
		for (auto i = 1; i < int(components.size()); ++i) {
			if (components[i] == library) {
				addHomeRoot(
					classifier._homeRoots,
					Components(components.begin(), components.begin() + i));
			}
		}
		return classifier.ClassifyComponents(components);
	};
	for (const auto &candidate : candidates) {
		const auto candidateClass = classify(candidate.folded, true);
		if (candidateClass != ProtectedClass::None) {
			if (failure) {
				failure->protectedClass = candidateClass;
			}
			return result;
		}
		const auto resolved = Walk(
			ParsedPath{.absolute = true, .components = candidate.traversal},
			filesystem, classify,
			[](const Components &) { return ProtectedClass::None; },
			[](const Components &) { return false; }, false, true);
		if (resolved.status != WalkResult::Status::Allowed
			|| resolved.components.empty()
			|| resolved.finalType != FileType::Directory) {
			if (failure && resolved.status == WalkResult::Status::Refused) {
				failure->protectedClass = resolved.protectedClass;
			}
			return result;
		}
		addHomeCandidates(resolved.components, preflightHomes);

		const auto physical = FoldedComponents(resolved.components);
		const auto accepted = std::vector<Components>{
			candidate.folded,
			physical,
			FoldedComponents(FirmlinkAlias(candidate.raw)),
			FoldedComponents(FirmlinkAlias(resolved.components)) };
		for (const auto &root : accepted) {
			if (std::none_of(
					result._homeRoots.begin(),
					result._homeRoots.end(),
					[&](const auto &existing) {
						return SameComponents(existing, root);
					})) {
				result._homeRoots.push_back(root);
			}
		}
	}
	if (result._homeRoots.empty()) {
		return result;
	}
	result._valid = true;
	return result;
}

bool MacProtectedPathPolicy::valid() const {
	return _valid;
}

ProtectedClass MacProtectedPathPolicy::Classify(
		const QByteArray &absolutePath) const {
	if (!_valid) {
		return ProtectedClass::Invalid;
	}
	ParsedPath parsed;
	if (!ParsePath(absolutePath, &parsed) || !parsed.absolute) {
		return ProtectedClass::Invalid;
	}
	return ClassifyComponents(FoldedComponents(parsed.components));
}

ProtectedClass MacProtectedPathPolicy::ClassifyComponents(
		const Components &components) const {
	if (!_valid) {
		return ProtectedClass::Invalid;
	}

	const auto library = Fold(QByteArray("Library"));
	const auto applicationSupport = Fold(QByteArray("Application Support"));
	const auto containers = Fold(QByteArray("Containers"));
	const auto groupContainers = Fold(QByteArray("Group Containers"));
	const auto application = Fold(QByteArray("Telegram Desktop"));
	const auto containerNames = ComponentsFromAscii({
		"org.telegram.desktop",
		"ru.keepcoder.telegram" });
	const auto bundleParents = ComponentsFromAscii({
		"preferences",
		"caches",
		"httpstorages",
		"webkit",
		"saved application state" });
	const auto bundlePrefixes = ComponentsFromAscii({
		"com.tdesktop.telegram",
		"org.telegram.desktop",
		"ru.keepcoder.telegram" });

	for (const auto &home : _homeRoots) {
		if (!StartsWith(components, home)
			|| components.size() == home.size()) {
			continue;
		}
		const auto offset = home.size();
		if (components.size() >= offset + 3
			&& components[offset] == library
			&& components[offset + 1] == applicationSupport
			&& components[offset + 2] == application) {
			return ProtectedClass::ApplicationSupport;
		}
		if (components.size() >= offset + 3
			&& components[offset] == library
			&& components[offset + 1] == containers
			&& std::find(
				containerNames.begin(),
				containerNames.end(),
				components[offset + 2]) != containerNames.end()) {
			return ProtectedClass::Container;
		}
		if (components.size() >= offset + 3
			&& components[offset] == library
			&& components[offset + 1] == groupContainers
			&& components[offset + 2].contains(Fold(QByteArray("telegram")))) {
			return ProtectedClass::GroupContainer;
		}
		if (components.size() >= offset + 3
			&& components[offset] == library
			&& std::find(
				bundleParents.begin(),
				bundleParents.end(),
				components[offset + 1]) != bundleParents.end()
			&& std::any_of(
				bundlePrefixes.begin(),
				bundlePrefixes.end(),
				[&](const auto &prefix) {
					return components[offset + 2].startsWith(prefix);
				})) {
			return ProtectedClass::BundleKeyed;
		}
	}
	return ProtectedClass::None;
}

ProtectedClass MacProtectedPathPolicy::ClassifyAncestorComponents(
		const Components &components) const {
	const auto library = Fold(QByteArray("Library"));
	const auto parents = std::vector<std::pair<QString, ProtectedClass>>{
		{ Fold(QByteArray("Application Support")),
			ProtectedClass::ApplicationSupport },
		{ Fold(QByteArray("Containers")), ProtectedClass::Container },
		{ Fold(QByteArray("Group Containers")), ProtectedClass::GroupContainer },
		{ Fold(QByteArray("Preferences")), ProtectedClass::BundleKeyed },
		{ Fold(QByteArray("Caches")), ProtectedClass::BundleKeyed },
		{ Fold(QByteArray("HTTPStorages")), ProtectedClass::BundleKeyed },
		{ Fold(QByteArray("WebKit")), ProtectedClass::BundleKeyed },
		{ Fold(QByteArray("Saved Application State")),
			ProtectedClass::BundleKeyed } };
	for (const auto &home : _homeRoots) {
		if (StartsWith(home, components)) {
			return ProtectedClass::ApplicationSupport;
		}
		if (!StartsWith(components, home)) {
			continue;
		}
		const auto offset = home.size();
		if (components.size() == offset + 1
			&& components[offset] == library) {
			return ProtectedClass::ApplicationSupport;
		}
		if (components.size() == offset + 2
			&& components[offset] == library) {
			for (const auto &[parent, protectedClass] : parents) {
				if (components[offset + 1] == parent) {
					return protectedClass;
				}
			}
		}
	}
	return ProtectedClass::None;
}

bool MacProtectedPathPolicy::IsHomeRoot(
		const Components &components) const {
	return std::any_of(
		_homeRoots.begin(),
		_homeRoots.end(),
		[&](const auto &home) { return SameComponents(components, home); });
}

Resolution MacProtectedPathPolicy::Resolve(
		Operation operation,
		const QByteArray &path,
		const QByteArray &anchor,
		const QString &callsite,
		RefusalLog *refusals) const {
	return ResolveBytes(operation, path, anchor, callsite, refusals);
}

Resolution MacProtectedPathPolicy::ResolveBytes(
		Operation operation,
		const QByteArray &path,
		const QByteArray &anchor,
		const QString &callsite,
		RefusalLog *refusals) const {
	if (!_valid) {
		return Refused(
			operation,
			ProtectedClass::Invalid,
			callsite,
			refusals);
	}
	ParsedPath parsed;
	if (!ParsePath(path, &parsed)) {
		return Refused(
			operation,
			ProtectedClass::Invalid,
			callsite,
			refusals);
	}
	if (!parsed.absolute) {
		ParsedPath parsedAnchor;
		if (!ParsePath(anchor, &parsedAnchor) || !parsedAnchor.absolute) {
			return Refused(
				operation,
				ProtectedClass::Invalid,
				callsite,
				refusals);
		}
		parsed.components.insert(
			parsed.components.begin(),
			parsedAnchor.components.begin(),
			parsedAnchor.components.end());
		parsed.absolute = true;
	}
	const auto classify = [&](const Components &components, bool final) {
		const auto protectedClass = ClassifyComponents(components);
		return (protectedClass == ProtectedClass::None
			&& final
			&& IsDestructive(operation))
			? ClassifyAncestorComponents(components)
			: protectedClass;
	};
	const auto lexical = classify(
		FoldedComponents(CanonicalRawComponents(parsed.components)),
		true);
	if (lexical != ProtectedClass::None) {
		return Refused(operation, lexical, callsite, refusals);
	}

	const auto walked = Walk(
		parsed, _filesystem, classify,
		[&](const Components &components) {
			if (!IsDestructive(operation)) {
				return ProtectedClass::None;
			}
			for (const auto &home : _homeRoots) {
				if (StartsWith(components, home)
					&& components.size() > home.size()) {
					return ClassifyAncestorComponents(components);
				}
			}
			return ProtectedClass::None;
		},
		[&](const Components &components) { return IsHomeRoot(components); },
		true, FollowsFinalComponent(operation));
	if (walked.status == WalkResult::Status::Refused) {
		return Refused(operation, walked.protectedClass, callsite, refusals);
	}
	if (walked.status != WalkResult::Status::Allowed) {
		return Refused(operation, ProtectedClass::Invalid, callsite, refusals);
	}
	return Allowed(walked.components);
}

PairResolution MacProtectedPathPolicy::ResolvePair(Operation operation,
												   const QByteArray &first,
												   const QByteArray &second,
												   const QByteArray &anchor,
												   const QString &callsite,
												   RefusalLog *refusals) const {
	return {
		Resolve(operation, first, anchor, callsite, refusals),
		Resolve(operation, second, anchor, callsite, refusals) };
}

} // namespace Core::MacProtectedPath
