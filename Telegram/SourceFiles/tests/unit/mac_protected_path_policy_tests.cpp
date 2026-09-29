/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "core/mac_protected_path_policy.h"

#include <map>
#include <vector>

namespace {

using namespace Core::MacProtectedPath;

struct FakeFileSystem final {
	std::map<QByteArray, LstatResult> entries;
	std::map<QByteArray, ReadlinkResult> links;
	std::vector<QByteArray> lstatCalls;
	std::vector<QByteArray> readlinkCalls;
	std::vector<QByteArray> openCalls;

	[[nodiscard]] FileSystem operations() {
		return {
			.lstat = [this](const QByteArray &path) {
				lstatCalls.push_back(path);
				const auto i = entries.find(path);
				return (i == entries.end())
					? LstatResult{ .error = FileError::Missing }
					: i->second;
			},
			.readlink = [this](const QByteArray &path) {
				readlinkCalls.push_back(path);
				const auto i = links.find(path);
				return (i == links.end())
					? ReadlinkResult{ .error = FileError::Unexpected }
					: i->second;
			},
			.open = [this](const QByteArray &path) {
				openCalls.push_back(path);
			}
		};
	}
};

[[nodiscard]] MacProtectedPathPolicy TestPolicy(FakeFileSystem &fs) {
	fs.entries.emplace(
		"/Users",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Users/alice",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	return MacProtectedPathPolicy::Build(
		HomeRoots{ .foundation = "/Users/alice" },
		fs.operations());
}

void ClearCalls(FakeFileSystem &fs) {
	fs.lstatCalls.clear();
	fs.readlinkCalls.clear();
	fs.openCalls.clear();
}

void CheckRefusedWithoutProtectedProbe(
		const MacProtectedPathPolicy &policy,
		FakeFileSystem &fs,
		const QByteArray &path,
		ProtectedClass protectedClass) {
	ClearCalls(fs);
	const auto result = policy.Resolve(
		Operation::Open,
		path,
		{},
		u"unit.probe"_q);
	CHECK(!result.allowed());
	CHECK(result.refusal.protectedClass == protectedClass);
	CHECK(result.resolvedPath.isEmpty());
	CHECK(fs.openCalls.empty());
	for (const auto &call : fs.lstatCalls) {
		CHECK(policy.Classify(call) == ProtectedClass::None);
	}
	for (const auto &call : fs.readlinkCalls) {
		CHECK(policy.Classify(call) == ProtectedClass::None);
	}
}

} // namespace

TEST_CASE(GroupContainerRefusesBeforeProtectedProbe) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	CHECK(policy.valid());

	const auto result = policy.Resolve(
		Operation::Open,
		"/Users/alice/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/tdata/x",
		{},
		u"unit.group-container"_q);
	CHECK(!result.allowed());
	CHECK(result.refusal.protectedClass == ProtectedClass::GroupContainer);
	CHECK(result.refusal.operation == Operation::Open);
	CHECK_EQ(result.refusal.callsite, u"unit.group-container"_q);
	CHECK(fs.openCalls.empty());
	CHECK(fs.readlinkCalls.empty());
	for (const auto &call : fs.lstatCalls) {
		CHECK(policy.Classify(call) != ProtectedClass::GroupContainer);
	}
}

TEST_CASE(AllProtectedRootsUseComponentMatching) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	const auto protectedPaths = std::vector<std::pair<QByteArray, ProtectedClass>>{
		{ "/Users/alice/Library/Application Support/Telegram Desktop/tdata/x",
			ProtectedClass::ApplicationSupport },
		{ "/Users/alice/Library/Containers/org.telegram.desktop/Data/x",
			ProtectedClass::Container },
		{ "/Users/alice/Library/Containers/ru.keepcoder.Telegram/Data/x",
			ProtectedClass::Container },
		{ "/Users/alice/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram/tdata/x",
			ProtectedClass::GroupContainer },
		{ "/Users/alice/Library/Preferences/com.tdesktop.Telegram.plist",
			ProtectedClass::BundleKeyed },
		{ "/Users/alice/Library/Caches/org.telegram.desktop/data",
			ProtectedClass::BundleKeyed },
		{ "/Users/alice/Library/HTTPStorages/ru.keepcoder.Telegram.shared/data",
			ProtectedClass::BundleKeyed },
		{ "/Users/alice/Library/WebKit/com.tdesktop.Telegramd/WebsiteData",
			ProtectedClass::BundleKeyed },
		{ "/Users/alice/Library/Saved Application State/org.telegram.desktop.savedState",
			ProtectedClass::BundleKeyed },
	};
	for (const auto &[path, protectedClass] : protectedPaths) {
		CHECK(policy.Classify(path) == protectedClass);
		CheckRefusedWithoutProtectedProbe(policy, fs, path, protectedClass);
	}

	const auto allowedPaths = std::vector<QByteArray>{
		"/Users/alice/Library/Application Support/Telegramd/tdata/x",
		"/Users/alice/Library/Application Support/Telegram Desktop.bak/tdata/x",
		"/Users/alice/Library/Containers/com.example.other/Data/x",
		"/Users/alice/Library/Group Containers/Signal/tdata/x",
		"/Users/alice/Library/Preferences/com.adambenhassen.telegramd.plist",
	};
	for (const auto &path : allowedPaths) {
		CHECK(policy.Classify(path) == ProtectedClass::None);
		ClearCalls(fs);
		const auto result = policy.Resolve(
			Operation::Open,
			path,
			{},
			u"unit.allowed"_q);
		CHECK(result.allowed());
	}
}

TEST_CASE(CaseNormalizationAndFirmlinkAliasesMatch) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);

	const auto mixedCase = QByteArray(
		"/uSeRs/ALICE/lIbRaRy/aPpLiCaTiOn sUpPoRt/telegram desktop/tdata");
	CHECK(policy.Classify(mixedCase) == ProtectedClass::ApplicationSupport);
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		mixedCase,
		ProtectedClass::ApplicationSupport);

	const auto ignored =
		u"/Users/alice/Library/Application Support/Tele\u200Bgram Desktop/tdata"_q;
	CHECK(policy.Classify(ignored.toUtf8()) == ProtectedClass::ApplicationSupport);

	const auto nfd =
		u"/Users/alice/Library/Application Support/Telegram Desktop/tdata"_q
			.normalized(QString::NormalizationForm_D);
	CHECK(policy.Classify(nfd.toUtf8()) == ProtectedClass::ApplicationSupport);

	auto unicodeFs = FakeFileSystem();
	unicodeFs.entries.emplace(
		"/Users",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	const auto unicodeHome = u"/Users/\u00C9lise"_q;
	unicodeFs.entries.emplace(
		unicodeHome.toUtf8(),
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	const auto unicodePolicy = MacProtectedPathPolicy::Build(
		HomeRoots{ .foundation = unicodeHome.toUtf8() },
		unicodeFs.operations());
	CHECK(unicodePolicy.valid());
	const auto decomposedHome = unicodeHome.normalized(
		QString::NormalizationForm_D);
	const auto decomposedPath = decomposedHome
		+ u"/Library/Application Support/Telegram Desktop/tdata"_q;
	CHECK(unicodePolicy.Classify(decomposedPath.toUtf8())
		== ProtectedClass::ApplicationSupport);

	const auto firmlink = QByteArray(
		"/System/Volumes/Data/Users/alice/Library/Group Containers/telegramd/tdata");
	CHECK(policy.Classify(firmlink) == ProtectedClass::GroupContainer);
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		firmlink,
		ProtectedClass::GroupContainer);
}

TEST_CASE(HomeRootsFromAllSourcesAreProtected) {
	auto fs = FakeFileSystem();
	fs.entries.emplace(
		"/Users",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Users/alice",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Users/bob",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Users/carol",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	const auto policy = MacProtectedPathPolicy::Build(
		HomeRoots{
			.accountDatabase = "/Users/alice",
			.environment = "/Users/bob",
			.foundation = "/Users/carol" },
		fs.operations());
	CHECK(policy.valid());
	CHECK(policy.Classify(
		"/Users/alice/Library/Application Support/Telegram Desktop/x")
		== ProtectedClass::ApplicationSupport);
	CHECK(policy.Classify(
		"/Users/bob/Library/Group Containers/telegram-work/x")
		== ProtectedClass::GroupContainer);
	CHECK(policy.Classify(
		"/Users/carol/Library/Caches/org.telegram.desktop/x")
		== ProtectedClass::BundleKeyed);
}

TEST_CASE(BuildRejectsProtectedHomeCandidateWithoutProbing) {
	auto fs = FakeFileSystem();
	const auto directories = std::vector<QByteArray>{
		"/Users",
		"/Users/alice",
		"/Users/alice/Library",
		"/Users/alice/Library/Group Containers" };
	for (const auto &path : directories) {
		fs.entries.emplace(
			path,
			LstatResult{ .type = FileType::Directory, .error = FileError::None });
	}
	const auto protectedRoot = QByteArray(
		"/Users/alice/Library/Group Containers/"
		"6N38VWS5BX.ru.keepcoder.Telegram");
	const auto protectedPrefix = protectedRoot + QByteArray("/");
	const auto policy = MacProtectedPathPolicy::Build(
		HomeRoots{
			.environment = protectedRoot + QByteArray("/tdata") },
		fs.operations());
	CHECK(!policy.valid());
	for (const auto &call : fs.lstatCalls) {
		CHECK(call != protectedRoot);
		CHECK(!call.startsWith(protectedPrefix));
	}
	for (const auto &call : fs.readlinkCalls) {
		CHECK(call != protectedRoot);
		CHECK(!call.startsWith(protectedPrefix));
	}
	CHECK(fs.openCalls.empty());
}

TEST_CASE(RelativeInputsRequireAnAnchorAndResolveAgainstIt) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);

	const auto relative = policy.Resolve(
		Operation::Stat,
		"Library/Group Containers/telegramd/tdata",
		"/Users/alice",
		u"unit.relative"_q);
	CHECK(!relative.allowed());
	CHECK(relative.refusal.protectedClass == ProtectedClass::GroupContainer);

	const auto withoutAnchor = policy.Resolve(
		Operation::Stat,
		"Library/Group Containers/telegramd/tdata",
		{},
		u"unit.relative.no-anchor"_q);
	CHECK(!withoutAnchor.allowed());
	CHECK(withoutAnchor.refusal.protectedClass == ProtectedClass::Invalid);

	const auto relativeAnchor = policy.Resolve(
		Operation::Stat,
		"Library/Group Containers/telegramd/tdata",
		"relative/base",
		u"unit.relative.bad-anchor"_q);
	CHECK(!relativeAnchor.allowed());
	CHECK(relativeAnchor.refusal.protectedClass == ProtectedClass::Invalid);
}

TEST_CASE(DotSegmentsAreResolvedBeforeFilesystemProbes) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	for (const auto &directory : std::vector<QByteArray>{
			 "/Users/alice/Library",
			 "/Users/alice/Library/Application Support",
			 "/Users/alice/Library/Application Support/Telegramd",
			 "/Users/alice/Library/Application Support/Telegramd/tdata" }) {
		fs.entries[directory] = LstatResult{
			.type = FileType::Directory,
			.error = FileError::None };
	}
	const auto path = QByteArray(
		"//Users/alice/./Library/Application Support/Telegramd/../"
		"Telegram Desktop/tdata");
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		path,
		ProtectedClass::ApplicationSupport);

	ClearCalls(fs);
	const auto allowed = policy.Resolve(
		Operation::Open,
		"/Users/alice/Library/Application Support/Telegramd/./tdata/../x",
		{},
		u"unit.dot.allowed"_q);
	CHECK(allowed.allowed());
	CHECK_EQ(
		allowed.resolvedPath,
		QByteArray("/Users/alice/Library/Application Support/Telegramd/x"));
}

TEST_CASE(DotDotAfterMissingComponentFailsClosed) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	fs.entries["/safe"] =
		LstatResult{ .type = FileType::Directory, .error = FileError::None };
	fs.entries["/safe/link"] =
		LstatResult{ .type = FileType::Symlink, .error = FileError::None };
	fs.links["/safe/link"] = ReadlinkResult{
		.target = "/Users/alice/Library/Group Containers/telegramd",
		.error = FileError::None };

	ClearCalls(fs);
	const auto result = policy.Resolve(
		Operation::Open,
		"/safe/missing/../link/tdata",
		{},
		u"unit.missing-parent"_q);
	CHECK(!result.allowed());
	CHECK(result.refusal.protectedClass == ProtectedClass::Invalid);
	CHECK_EQ(int(fs.lstatCalls.size()), 2);
	CHECK_EQ(fs.lstatCalls[0], QByteArray("/safe"));
	CHECK_EQ(fs.lstatCalls[1], QByteArray("/safe/missing"));
	CHECK(fs.readlinkCalls.empty());
	CHECK(fs.openCalls.empty());
}

TEST_CASE(SymlinkTargetsAreSplicedPhysically) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	fs.entries.emplace(
		"/safe",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/safe/link",
		LstatResult{ .type = FileType::Symlink, .error = FileError::None });
	fs.links.emplace(
		"/safe/link",
		ReadlinkResult{
			.target = "/Users/alice/Library/Application Support/Telegram Desktop",
			.error = FileError::None });
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		"/safe/link/tdata",
		ProtectedClass::ApplicationSupport);

	ClearCalls(fs);
	fs.entries["/safe/relative"] =
		LstatResult{ .type = FileType::Symlink, .error = FileError::None };
	fs.links["/safe/relative"] = ReadlinkResult{
		.target = "../Users/alice/Library/Group Containers/telegramd",
		.error = FileError::None };
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		"/safe/relative/tdata",
		ProtectedClass::GroupContainer);

	ClearCalls(fs);
	fs.entries["/safe/dangling"] =
		LstatResult{ .type = FileType::Symlink, .error = FileError::None };
	fs.links["/safe/dangling"] = ReadlinkResult{
		.target = "/Users/alice/Library/Containers/org.telegram.desktop",
		.error = FileError::None };
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		"/safe/dangling/tdata",
		ProtectedClass::Container);
}

TEST_CASE(SymlinkHopLimitAndFilesystemErrorsFailClosed) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	fs.entries.emplace(
		"/safe",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	for (auto i = 0; i != 32; ++i) {
		const auto name = QByteArray("/safe/link") + QByteArray::number(i);
		const auto target = (i == 31)
			? QByteArray("/safe/target")
			: QByteArray("/safe/link") + QByteArray::number(i + 1);
		fs.entries[name] =
			LstatResult{ .type = FileType::Symlink, .error = FileError::None };
		fs.links[name] = ReadlinkResult{
			.target = target,
			.error = FileError::None };
	}
	fs.entries.emplace(
		"/safe/target",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	const auto chain = policy.Resolve(
		Operation::Open,
		"/safe/link0/tdata",
		{},
		u"unit.chain"_q);
	CHECK(chain.allowed());

	for (auto i = 0; i != 32; ++i) {
		const auto name = QByteArray("/safe/loop") + QByteArray::number(i);
		const auto target = (i == 31)
			? QByteArray("/safe/loop0")
			: QByteArray("/safe/loop") + QByteArray::number(i + 1);
		fs.entries[name] =
			LstatResult{ .type = FileType::Symlink, .error = FileError::None };
		fs.links[name] = ReadlinkResult{
			.target = target,
			.error = FileError::None };
	}
	const auto loop = policy.Resolve(
		Operation::Open,
		"/safe/loop0/tdata",
		{},
		u"unit.loop"_q);
	CHECK(!loop.allowed());
	CHECK(loop.refusal.protectedClass == ProtectedClass::Invalid);

	fs.entries["/broken"] =
		LstatResult{ .error = FileError::Unexpected };
	const auto unexpected = policy.Resolve(
		Operation::Open,
		"/broken/path",
		{},
		u"unit.error"_q);
	CHECK(!unexpected.allowed());
	CHECK(unexpected.refusal.protectedClass == ProtectedClass::Invalid);

	fs.entries["/ambiguous"] =
		LstatResult{ .error = FileError::Ambiguous };
	const auto ambiguous = policy.Resolve(
		Operation::Open,
		"/ambiguous/path",
		{},
		u"unit.ambiguous"_q);
	CHECK(!ambiguous.allowed());
	CHECK(ambiguous.refusal.protectedClass == ProtectedClass::Invalid);
}

TEST_CASE(RealpathHomeAliasesAndFirmlinksShareTheBoundary) {
	auto fs = FakeFileSystem();
	fs.entries.emplace(
		"/Aliases",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Aliases/alice",
		LstatResult{ .type = FileType::Symlink, .error = FileError::None });
	fs.links.emplace(
		"/Aliases/alice",
		ReadlinkResult{
			.target = "/Users/alice",
			.error = FileError::None });
	fs.entries.emplace(
		"/Users",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	fs.entries.emplace(
		"/Users/alice",
		LstatResult{ .type = FileType::Directory, .error = FileError::None });
	const auto policy = MacProtectedPathPolicy::Build(
		HomeRoots{ .foundation = "/Aliases/alice" },
		fs.operations());
	CHECK(policy.valid());

	const auto canonical = QByteArray(
		"/Users/alice/Library/Application Support/Telegram Desktop/x");
	const auto alias = QByteArray(
		"/Aliases/alice/Library/Application Support/Telegram Desktop/x");
	const auto firmlink = QByteArray(
		"/System/Volumes/Data/Users/alice/Library/Application Support/Telegram Desktop/x");
	CHECK(policy.Classify(canonical) == ProtectedClass::ApplicationSupport);
	CHECK(policy.Classify(alias) == ProtectedClass::ApplicationSupport);
	CHECK(policy.Classify(firmlink) == ProtectedClass::ApplicationSupport);
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		canonical,
		ProtectedClass::ApplicationSupport);
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		alias,
		ProtectedClass::ApplicationSupport);
	CheckRefusedWithoutProtectedProbe(
		policy,
		fs,
		firmlink,
		ProtectedClass::ApplicationSupport);
}

TEST_CASE(InvalidNamesAndMissingHomesFailClosed) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	const auto invalid = QByteArray("/safe/")
		+ QByteArray::fromHex("ff")
		+ "/path";
	ClearCalls(fs);
	const auto invalidResult = policy.Resolve(
		Operation::Open,
		invalid,
		{},
		u"unit.invalid-name"_q);
	CHECK(!invalidResult.allowed());
	CHECK(invalidResult.refusal.protectedClass == ProtectedClass::Invalid);
	CHECK(fs.lstatCalls.empty());
	CHECK(fs.readlinkCalls.empty());

	fs.entries["/safe"] =
		LstatResult{ .type = FileType::Directory, .error = FileError::None };
	fs.entries["/safe/link"] =
		LstatResult{ .type = FileType::Symlink, .error = FileError::None };
	fs.links["/safe/link"] = ReadlinkResult{
		.target = QByteArray::fromHex("ff"),
		.error = FileError::None };
	const auto invalidTarget = policy.Resolve(
		Operation::Open,
		"/safe/link/path",
		{},
		u"unit.invalid-target"_q);
	CHECK(!invalidTarget.allowed());
	CHECK(invalidTarget.refusal.protectedClass == ProtectedClass::Invalid);

	auto missingHomeFs = FakeFileSystem();
	const auto missingHome = MacProtectedPathPolicy::Build(
		HomeRoots{ .foundation = "/Users/alice" },
		missingHomeFs.operations());
	CHECK(!missingHome.valid());
	const auto missingResult = missingHome.Resolve(
		Operation::Open,
		"/Users/alice/Library/Application Support/Telegram Desktop/x",
		{},
		u"unit.missing-home"_q);
	CHECK(!missingResult.allowed());
	CHECK(missingResult.refusal.protectedClass == ProtectedClass::Invalid);
}

TEST_CASE(RefusalRecordsAreRateLimitedWithoutPaths) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	auto now = qint64(100);
	auto log = RefusalLog([&] { return now; });

	const auto first = policy.Resolve(
		Operation::Open,
		"/Users/alice/Library/Group Containers/telegramd/x",
		{},
		u"unit.first"_q,
		&log);
	const auto second = policy.Resolve(
		Operation::Open,
		"/Users/alice/Library/Group Containers/telegramd/y",
		{},
		u"unit.second"_q,
		&log);
	CHECK(!first.allowed());
	CHECK(!second.allowed());
	CHECK_EQ(int(log.records().size()), 1);
	CHECK_EQ(log.records().front().callsite, u"unit.first"_q);

	now = 160;
	const auto third = policy.Resolve(
		Operation::Open,
		"/Users/alice/Library/Group Containers/telegramd/z",
		{},
		u"unit.third"_q,
		&log);
	CHECK(!third.allowed());
	CHECK_EQ(int(log.records().size()), 2);
	CHECK_EQ(log.records().back().callsite, u"unit.third"_q);
}

TEST_CASE(OperationAndPairChecksCoverBothEndpoints) {
	auto fs = FakeFileSystem();
	const auto policy = TestPolicy(fs);
	const auto protectedPath = QByteArray(
		"/Users/alice/Library/Application Support/Telegram Desktop/x");
	const auto operations = std::vector<Operation>{
		Operation::Open,
		Operation::Read,
		Operation::Write,
		Operation::Stat,
		Operation::Lstat,
		Operation::OpenDir,
		Operation::GetAttrList,
		Operation::Mkdir,
		Operation::Lock,
		Operation::Rename,
		Operation::Copy,
		Operation::Link,
		Operation::Unlink,
		Operation::Rmdir,
		Operation::RecursiveDelete,
	};
	for (const auto operation : operations) {
		const auto result = policy.Resolve(
			operation,
			protectedPath,
			{},
			u"unit.operation"_q);
		CHECK(!result.allowed());
		CHECK(result.refusal.operation == operation);
	}

	const auto pair = policy.ResolvePair(
		Operation::Rename,
		"/safe/source",
		protectedPath,
		{},
		u"unit.pair"_q);
	CHECK(pair.first.allowed());
	CHECK(!pair.second.allowed());
	CHECK(pair.second.refusal.protectedClass == ProtectedClass::ApplicationSupport);
	const auto reversedPair = policy.ResolvePair(
		Operation::Copy,
		protectedPath,
		"/safe/destination",
		{},
		u"unit.reversed-pair"_q);
	CHECK(!reversedPair.first.allowed());
	CHECK(reversedPair.second.allowed());
	CHECK(reversedPair.first.refusal.protectedClass
		== ProtectedClass::ApplicationSupport);
	for (const auto &call : fs.lstatCalls) {
		CHECK(policy.Classify(call) == ProtectedClass::None);
	}
}
