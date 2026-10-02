/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "core/local_url_conversion.h"

#include <QtCore/QStringList>

#include <utility>
#include <vector>

namespace {

const auto kServerPrefix =
	u"https://telegram-server.tailaa4918.ts.net/"_q;

TEST_CASE(PinnedServerInviteLinkOpensJoinFlow) {
	CHECK_EQ(
		Core::TryConvertUrlToLocal(
			u"https://telegram-server.tailaa4918.ts.net/+example"_q,
			kServerPrefix,
			true),
		u"tg://join?invite=example"_q);
}

TEST_CASE(PinnedServerUsernameLinkResolvesUsername) {
	CHECK_EQ(
		Core::TryConvertUrlToLocal(
			u"https://telegram-server.tailaa4918.ts.net/example"_q,
			kServerPrefix,
			true),
		u"tg://resolve?domain=example"_q);
}

TEST_CASE(PinnedServerLinkCannotSelectAnotherLoggedInAccount) {
	const auto links = QStringList{
		u"https://telegram-server.tailaa4918.ts.net/example?acc=2"_q,
		u"https://telegram-server.tailaa4918.ts.net/example?ACC=2"_q,
		u"https://telegram-server.tailaa4918.ts.net/example?%61cc=2"_q,
	};
	for (const auto &link : links) {
		CHECK_EQ(
			Core::TryConvertUrlToLocal(link, kServerPrefix, true),
			u"tg://resolve?domain=example"_q);
	}
	CHECK_EQ(
		Core::TryConvertUrlToLocal(
			u"https://telegram-server.tailaa4918.ts.net/example?start=token&acc=2"_q,
			kServerPrefix,
			true),
		u"tg://resolve?domain=example&start=token"_q);
}

TEST_CASE(PinnedServerPublicMessageLinkOpensMessage) {
	CHECK_EQ(
		Core::TryConvertUrlToLocal(
			u"https://telegram-server.tailaa4918.ts.net/example/123"_q,
			kServerPrefix,
			true),
		u"tg://resolve?domain=example&post=123"_q);
}

TEST_CASE(PinnedServerPrivateMessageLinkOpensMessage) {
	CHECK_EQ(
		Core::TryConvertUrlToLocal(
			u"https://telegram-server.tailaa4918.ts.net/c/123/456"_q,
			kServerPrefix,
			true),
		u"tg://privatepost?channel=123&post=456"_q);
}

TEST_CASE(PinnedServerOriginMatchesHostCaseInsensitively) {
	CHECK_EQ(
		Core::TryConvertUrlToLocal(
			u"HTTPS://TELEGRAM-SERVER.TAILAA4918.TS.NET/Example/123"_q,
			kServerPrefix,
			true),
		u"tg://resolve?domain=Example&post=123"_q);
}

TEST_CASE(PinnedServerOriginAcceptsOnlyDefaultPort) {
	CHECK_EQ(
		Core::TryConvertUrlToLocal(
			u"https://telegram-server.tailaa4918.ts.net:443/example"_q,
			kServerPrefix,
			true),
		u"tg://resolve?domain=example"_q);
	const auto nonDefault =
		u"https://telegram-server.tailaa4918.ts.net:8443/example"_q;
	CHECK_EQ(
		Core::TryConvertUrlToLocal(
			nonDefault,
			kServerPrefix,
			true),
		nonDefault);
}

TEST_CASE(OfficialAndContextlessLinksDoNotUsePinnedOrigin) {
	const auto url =
		u"https://telegram-server.tailaa4918.ts.net/+example"_q;
	CHECK_EQ(
		Core::TryConvertUrlToLocal(url, kServerPrefix, false),
		url);
	CHECK_EQ(Core::TryConvertUrlToLocal(url), url);
}

TEST_CASE(ThreatModelLookalikeOriginsStayExternal) {
	const auto urls = QStringList{
		u"https://telegram-server.tailaa4918.ts.net@evil.example/+x"_q,
		u"https://evil.example@telegram-server.tailaa4918.ts.net/+x"_q,
		u"https://telegram-server.tailaa4918.ts.net.evil.example/+x"_q,
		u"https://evil-telegram-server.tailaa4918.ts.net/+x"_q,
		u"https://telegram-server.tailaa4918.ts.net./+x"_q,
		u"https://t\u0435legram-server.tailaa4918.ts.net/+x"_q,
		u"https://xn--telegram-server.tailaa4918.ts.net/+x"_q,
		u"http://telegram-server.tailaa4918.ts.net/+x"_q,
	};
	for (const auto &url : urls) {
		CHECK_EQ(
			Core::TryConvertUrlToLocal(url, kServerPrefix, true),
			url);
	}
}

TEST_CASE(IdnConfiguredOriginStaysExternal) {
	const auto prefix = u"https://xn--telegram-server.tailaa4918.ts.net/"_q;
	const auto url = u"https://xn--telegram-server.tailaa4918.ts.net/+x"_q;
	CHECK_EQ(Core::TryConvertUrlToLocal(url, prefix, true), url);
}

TEST_CASE(InvalidConfiguredOriginsDoNotEnableConversion) {
	const auto url =
		u"https://telegram-server.tailaa4918.ts.net/+example"_q;
	const auto prefixes = QStringList{
		u"http://telegram-server.tailaa4918.ts.net/"_q,
		u"https://user@telegram-server.tailaa4918.ts.net/"_q,
		u"https://telegram-server.tailaa4918.ts.net:8443/"_q,
		u"https://127.0.0.1/"_q,
		u"https://telegram-server.tailaa4918.ts.net/path/"_q,
		u"https://telegram-server.tailaa4918.ts.net/?query=value"_q,
	};
	for (const auto &prefix : prefixes) {
		CHECK_EQ(Core::TryConvertUrlToLocal(url, prefix, true), url);
	}
}

TEST_CASE(UnsupportedConfiguredPathsStayExternal) {
	const auto links = QStringList{
		u"https://telegram-server.tailaa4918.ts.net/"_q,
		u"https://telegram-server.tailaa4918.ts.net/example/unsupported/path"_q,
		u"https://telegram-server.tailaa4918.ts.net/iv?url=https://example.com"_q,
	};
	for (const auto &link : links) {
		CHECK_EQ(
			Core::TryConvertUrlToLocal(link, kServerPrefix, true),
			link);
	}
}

TEST_CASE(LegacyTelegramLinksKeepInAppConversions) {
	const auto links = std::vector<std::pair<QString, QString>>{
		{
			u"https://t.me/+example"_q,
			u"tg://join?invite=example"_q,
		},
		{
			u"https://t.me/example"_q,
			u"tg://resolve?domain=example"_q,
		},
		{
			u"https://t.me/example/123"_q,
			u"tg://resolve?domain=example&post=123"_q,
		},
		{
			u"https://t.me/example?acc=2"_q,
			u"tg://resolve?domain=example&acc=2"_q,
		},
		{
			u"https://t.me/c/123/456"_q,
			u"tg://privatepost?channel=123&post=456"_q,
		},
	};
	for (const auto &[link, want] : links) {
		CHECK_EQ(Core::TryConvertUrlToLocal(link), want);
		CHECK_EQ(Core::TryConvertUrlToLocal(link, kServerPrefix, false), want);
		CHECK_EQ(Core::TryConvertUrlToLocal(link, kServerPrefix, true), want);
	}
}

} // namespace
