/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/local_url_conversion.h"

#include "base/qthelp_regex.h"
#include "base/qthelp_url.h"

#include <QtCore/QStringList>
#include <QtCore/QUrl>

#include <algorithm>
#include <optional>
#include <utility>

namespace Core {
namespace {

struct HttpsOrigin {
	QString host;
	qsizetype authorityEnd = 0;
};

[[nodiscard]] bool IsOfficialTelegramHost(const QString &host) {
	const auto normalized = host.startsWith(u"www."_q, Qt::CaseInsensitive)
		? host.mid(4)
		: host;
	return (normalized.compare(u"t.me"_q, Qt::CaseInsensitive) == 0)
		|| (normalized.compare(u"telegram.me"_q, Qt::CaseInsensitive) == 0)
		|| (normalized.compare(u"telegram.dog"_q, Qt::CaseInsensitive) == 0);
}

[[nodiscard]] bool IsAsciiHostname(const QString &host) {
	if (host.isEmpty() || host.size() > 253 || host.endsWith('.')) {
		return false;
	}
	auto numericHost = true;
	for (const auto c : host) {
		numericHost = numericHost && ((c >= '0' && c <= '9') || (c == '.'));
	}
	if (numericHost) {
		return false;
	}
	auto labelStart = qsizetype(0);
	for (auto i = qsizetype(0); i <= host.size(); ++i) {
		if (i != host.size() && host[i] != '.') {
			const auto c = host[i];
			if (!((c >= 'a' && c <= 'z')
				|| (c >= 'A' && c <= 'Z')
				|| (c >= '0' && c <= '9')
				|| (c == '-'))) {
				return false;
			}
			continue;
		}
		const auto labelSize = i - labelStart;
		if (!labelSize
			|| labelSize > 63
			|| host[labelStart] == '-'
			|| host[i - 1] == '-'
			|| host.mid(labelStart, 4).compare(
				u"xn--"_q,
				Qt::CaseInsensitive) == 0) {
			return false;
		}
		labelStart = i + 1;
	}
	return true;
}

[[nodiscard]] std::optional<HttpsOrigin> ParseHttpsOrigin(
		const QString &url,
		bool requireOriginOnly) {
	const auto schemeEnd = url.indexOf(u"://"_q);
	if (schemeEnd < 0
		|| url.left(schemeEnd).compare(u"https"_q, Qt::CaseInsensitive) != 0) {
		return std::nullopt;
	}
	const auto authorityStart = schemeEnd + 3;
	auto authorityEnd = url.size();
	for (const auto delimiter : { u'/', u'?', u'#' }) {
		const auto index = url.indexOf(QChar(delimiter), authorityStart);
		if (index >= 0) {
			authorityEnd = std::min(authorityEnd, index);
		}
	}
	const auto authority = url.mid(
		authorityStart,
		authorityEnd - authorityStart);
	if (authority.isEmpty() || authority.contains('@') || authority.contains('%')) {
		return std::nullopt;
	}
	auto host = authority;
	const auto portSeparator = authority.indexOf(':');
	if (portSeparator >= 0) {
		if (authority.indexOf(':', portSeparator + 1) >= 0) {
			return std::nullopt;
		}
		const auto portText = authority.mid(portSeparator + 1);
		if (portText.isEmpty()) {
			return std::nullopt;
		}
		for (const auto c : portText) {
			if (c < '0' || c > '9') {
				return std::nullopt;
			}
		}
		bool ok = false;
		if (portText.toInt(&ok) != 443 || !ok) {
			return std::nullopt;
		}
		host = authority.left(portSeparator);
	}
	if (!IsAsciiHostname(host)) {
		return std::nullopt;
	}
	const auto parsed = QUrl(url, QUrl::StrictMode);
	if (!parsed.isValid()
		|| parsed.scheme().compare(u"https"_q, Qt::CaseInsensitive) != 0
		|| parsed.host().compare(host, Qt::CaseInsensitive) != 0
		|| (parsed.port(-1) != -1 && parsed.port(-1) != 443)) {
		return std::nullopt;
	}
	if (requireOriginOnly
		&& !parsed.path().isEmpty()
		&& parsed.path() != u"/"_q) {
		return std::nullopt;
	}
	if (requireOriginOnly && (parsed.hasQuery() || parsed.hasFragment())) {
		return std::nullopt;
	}
	return HttpsOrigin{ .host = std::move(host), .authorityEnd = authorityEnd };
}

[[nodiscard]] std::optional<QString> CustomOriginUrlAsTelegramUrl(
		const QString &url,
		const QString &internalLinksDomain) {
	const auto configured = ParseHttpsOrigin(internalLinksDomain, true);
	const auto source = ParseHttpsOrigin(url, false);
	if (!configured
		|| !source
		|| IsOfficialTelegramHost(configured->host)
		|| configured->host.compare(source->host, Qt::CaseInsensitive) != 0) {
		return std::nullopt;
	}
	auto suffix = url.mid(source->authorityEnd);
	if (!suffix.startsWith('/')) {
		return std::nullopt;
	}
	const auto fragmentStart = suffix.indexOf(QChar(u'#'));
	if (fragmentStart >= 0) {
		suffix = suffix.left(fragmentStart);
	}
	return u"https://t.me"_q + suffix;
}

[[nodiscard]] QString WithoutAccountIndex(QString url) {
	const auto queryStart = url.indexOf(QChar(u'?'));
	if (queryStart < 0) {
		return url;
	}
	const auto fragmentStart = url.indexOf(QChar(u'#'), queryStart + 1);
	const auto queryEnd = (fragmentStart < 0) ? url.size() : fragmentStart;
	const auto query = url.mid(queryStart + 1, queryEnd - queryStart - 1);
	const auto parameters = query.split(QChar(u'&'), Qt::KeepEmptyParts);
	auto retained = QStringList();
	for (const auto &parameter : parameters) {
		const auto equals = parameter.indexOf(QChar(u'='));
		const auto name = (equals < 0) ? parameter : parameter.left(equals);
		const auto decodedName = QUrl::fromPercentEncoding(name.toUtf8());
		if (decodedName.compare(u"acc"_q, Qt::CaseInsensitive) != 0) {
			retained.push_back(parameter);
		}
	}
	if (retained.size() == parameters.size()) {
		return url;
	}
	return url.left(queryStart + 1)
		+ retained.join(u"&"_q)
		+ url.mid(queryEnd);
}

[[nodiscard]] QString ConvertLegacyUrlToLocal(QString url) {
	if (url.size() > 8192) {
		url = url.mid(0, 8192);
	}

	using namespace qthelp;
	auto matchOptions = RegExOption::CaseInsensitive;
	auto tonsiteMatch = (url.indexOf(u".ton") >= 0)
		? regex_match(u"^(https?://)?[^/@:]+\\.ton($|/)"_q, url, matchOptions)
		: RegularExpressionMatch(QRegularExpressionMatch());
	if (tonsiteMatch) {
		const auto protocol = tonsiteMatch->captured(1);
		return u"tonsite://"_q + url.mid(protocol.size());
	}
	auto subdomainMatch = regex_match(u"^(https?://)?([a-zA-Z0-9\\_]+)\\.t\\.me(/\\d+)?/?(\\?.+)?"_q, url, matchOptions);
	if (subdomainMatch) {
		const auto name = subdomainMatch->captured(2);
		if (name.size() > 1 && name != "www") {
			const auto result = ConvertLegacyUrlToLocal(
				subdomainMatch->captured(1)
				+ "t.me/"
				+ name
				+ subdomainMatch->captured(3)
				+ subdomainMatch->captured(4));
			return result.startsWith("tg://resolve?domain=")
				? result
				: url;
		}
	}
	auto telegramMeMatch = regex_match(u"^(https?://)?(www\\.)?(telegram\\.(me|dog)|t\\.me)/(.+)$"_q, url, matchOptions);
	if (telegramMeMatch) {
		const auto query = telegramMeMatch->capturedView(5);
		if (const auto phoneMatch = regex_match(u"^\\+([0-9]+)(\\?|$)"_q, query, matchOptions)) {
			const auto params = query.mid(phoneMatch->captured(0).size()).toString();
			return u"tg://resolve?phone="_q + phoneMatch->captured(1) + (params.isEmpty() ? QString() : '&' + params);
		} else if (const auto joinChatMatch = regex_match(u"^(joinchat/|\\+|\\%20)([a-zA-Z0-9\\.\\_\\-]+)(\\?|$)"_q, query, matchOptions)) {
			return u"tg://join?invite="_q + url_encode(joinChatMatch->captured(2));
		} else if (const auto joinFilterMatch = regex_match(u"^(addlist/)([a-zA-Z0-9\\.\\_\\-]+)(\\?|$)"_q, query, matchOptions)) {
			return u"tg://addlist?slug="_q + url_encode(joinFilterMatch->captured(2));
		} else if (const auto stickerSetMatch = regex_match(u"^(addstickers|addemoji)/([a-zA-Z0-9\\.\\_]+)(\\?|$)"_q, query, matchOptions)) {
			return u"tg://"_q + stickerSetMatch->captured(1) + "?set=" + url_encode(stickerSetMatch->captured(2));
		} else if (const auto themeMatch = regex_match(u"^addtheme/([a-zA-Z0-9\\.\\_]+)(\\?|$)"_q, query, matchOptions)) {
			return u"tg://addtheme?slug="_q + url_encode(themeMatch->captured(1));
		} else if (const auto addStyleMatch = regex_match(u"^addstyle/([a-zA-Z0-9\\.\\_]+)(\\?|$)"_q, query, matchOptions)) {
			return u"tg://addstyle?slug="_q + url_encode(addStyleMatch->captured(1));
		} else if (const auto languageMatch = regex_match(u"^setlanguage/([a-zA-Z0-9\\.\\_\\-]+)(\\?|$)"_q, query, matchOptions)) {
			return u"tg://setlanguage?lang="_q + url_encode(languageMatch->captured(1));
		} else if (const auto shareUrlMatch = regex_match(u"^share/url/?\\?(.+)$"_q, query, matchOptions)) {
			return u"tg://msg_url?"_q + shareUrlMatch->captured(1);
		} else if (const auto confirmPhoneMatch = regex_match(u"^confirmphone/?\\?(.+)"_q, query, matchOptions)) {
			return u"tg://confirmphone?"_q + confirmPhoneMatch->captured(1);
		} else if (const auto ivMatch = regex_match(u"^iv/?\\?(.+)(#|$)"_q, query, matchOptions)) {
			//
			// We need to show our t.me page, not the url directly.
			//
			//auto params = url_parse_params(ivMatch->captured(1), UrlParamNameTransform::ToLower);
			//auto previewedUrl = params.value(u"url"_q);
			//if (previewedUrl.startsWith(u"http://"_q, Qt::CaseInsensitive)
			//	|| previewedUrl.startsWith(u"https://"_q, Qt::CaseInsensitive)) {
			//	return previewedUrl;
			//}
			return url;
		} else if (const auto socksMatch = regex_match(u"^socks/?\\?(.+)(#|$)"_q, query, matchOptions)) {
			return u"tg://socks?"_q + socksMatch->captured(1);
		} else if (const auto proxyMatch = regex_match(u"^proxy/?\\?(.+)(#|$)"_q, query, matchOptions)) {
			return u"tg://proxy?"_q + proxyMatch->captured(1);
		} else if (const auto invoiceMatch = regex_match(u"^(invoice/|\\$)([a-zA-Z0-9_\\-]+)(\\?|#|$)"_q, query, matchOptions)) {
			return u"tg://invoice?slug="_q + invoiceMatch->captured(2);
		} else if (const auto bgMatch = regex_match(u"^bg/([a-zA-Z0-9\\.\\_\\-\\~]+)(\\?(.+)?)?$"_q, query, matchOptions)) {
			const auto params = bgMatch->captured(3);
			const auto bg = bgMatch->captured(1);
			const auto type = regex_match(u"^[a-fA-F0-9]{6}^"_q, bg)
				? "color"
				: (regex_match(u"^[a-fA-F0-9]{6}\\-[a-fA-F0-9]{6}$"_q, bg)
					|| regex_match(u"^[a-fA-F0-9]{6}(\\~[a-fA-F0-9]{6}){1,3}$"_q, bg))
				? "gradient"
				: "slug";
			return u"tg://bg?"_q + type + '=' + bg + (params.isEmpty() ? QString() : '&' + params);
		} else if (const auto chatlinkMatch = regex_match(u"^m/([a-zA-Z0-9\\.\\_\\-]+)(\\?|$)"_q, query, matchOptions)) {
			const auto slug = chatlinkMatch->captured(1);
			return u"tg://message?slug="_q + slug;
		} else if (const auto nftMatch = regex_match(u"^nft/([a-zA-Z0-9\\.\\_\\-]+)(\\?|$)"_q, query, matchOptions)) {
			const auto slug = nftMatch->captured(1);
			return u"tg://nft?slug="_q + slug;
		} else if (const auto auctionMatch = regex_match(u"^auction/([a-zA-Z0-9\\.\\_\\-]+)(\\?|$)"_q, query, matchOptions)) {
			const auto slug = auctionMatch->captured(1);
			return u"tg://stargift_auction?slug="_q + slug;
		} else if (const auto callMatch = regex_match(u"^call/([a-zA-Z0-9\\.\\_\\-]+)(\\?|$)"_q, query, matchOptions)) {
			const auto slug = callMatch->captured(1);
			return u"tg://call?slug="_q + slug;
		} else if (const auto newbotMatch = regex_match(u"^newbot/([a-zA-Z0-9\\.\\_]+)(/([a-zA-Z0-9\\.\\_]*))?(/?\\?(.+))?$"_q, query, matchOptions)) {
			const auto manager = newbotMatch->captured(1);
			const auto username = newbotMatch->captured(3);
			const auto params = newbotMatch->captured(5);
			auto result = u"tg://newbot?manager="_q + url_encode(manager);
			if (!username.isEmpty()) {
				result += u"&username="_q + url_encode(username);
			}
			if (!params.isEmpty()) {
				result += '&' + params;
			}
			return result;
		} else if (const auto privateMatch = regex_match(u"^"
			"c/(\\-?\\d+)"
			"("
				"/?\\?|"
				"/?$|"
				"/\\d+/?(\\?|$)|"
				"/\\d+/\\d+/?(\\?|$)"
			")"_q, query, matchOptions)) {
			const auto channel = privateMatch->captured(1);
			const auto params = query.mid(privateMatch->captured(0).size()).toString();
			if (params.indexOf("boost", 0, Qt::CaseInsensitive) >= 0
				&& params.toLower().split('&').contains(u"boost"_q)) {
				return u"tg://boost?channel="_q + channel;
			}
			const auto base = u"tg://privatepost?channel="_q + channel;
			auto added = QString();
			if (const auto threadPostMatch = regex_match(u"^/(\\d+)/(\\d+)(/?\\?|/?$)"_q, privateMatch->captured(2))) {
				added = u"&topic=%1&post=%2"_q.arg(threadPostMatch->captured(1), threadPostMatch->captured(2));
			} else if (const auto postMatch = regex_match(u"^/(\\d+)(/?\\?|/?$)"_q, privateMatch->captured(2))) {
				added = u"&post="_q + postMatch->captured(1);
			}
			return base + added + (params.isEmpty() ? QString() : '&' + params);
		} else if (const auto usernameMatch = regex_match(u"^"
			"([a-zA-Z0-9\\.\\_]+)"
			"("
				"/?\\?|"
				"/?$|"
				"/[a-zA-Z0-9\\.\\_\\-]+/?(\\?|$)|"
				"/\\d+/?(\\?|$)|"
				"/s/(\\d+|live)/?(\\?|$)|"
				"/a/\\d+/?(\\?|$)|"
				"/c/\\d+/?(\\?|$)|"
				"/\\d+/\\d+/?(\\?|$)"
			")"_q, query, matchOptions)) {
			const auto domain = usernameMatch->captured(1);
			const auto params = query.mid(usernameMatch->captured(0).size()).toString();
			if (params.indexOf("boost", 0, Qt::CaseInsensitive) >= 0
				&& params.toLower().split('&').contains(u"boost"_q)) {
				return u"tg://boost?domain="_q + domain;
			} else if (domain == u"boost"_q) {
				if (const auto domainMatch = regex_match(u"^/([a-zA-Z0-9\\.\\_]+)(/?\\?|/?$)"_q, usernameMatch->captured(2))) {
					return u"tg://boost?domain="_q + domainMatch->captured(1);
				} else if (params.indexOf("c=", 0, Qt::CaseInsensitive) >= 0) {
					return u"tg://boost?"_q + params;
				}
			}
			const auto base = u"tg://resolve?domain="_q + url_encode(usernameMatch->captured(1));
			auto added = QString();
			if (const auto threadPostMatch = regex_match(u"^/(\\d+)/(\\d+)(/?\\?|/?$)"_q, usernameMatch->captured(2))) {
				added = u"&topic=%1&post=%2"_q.arg(threadPostMatch->captured(1), threadPostMatch->captured(2));
			} else if (const auto postMatch = regex_match(u"^/(\\d+)(/?\\?|/?$)"_q, usernameMatch->captured(2))) {
				added = u"&post="_q + postMatch->captured(1);
			} else if (const auto storyMatch = regex_match(u"^/s/(\\d+|live)(/?\\?|/?$)"_q, usernameMatch->captured(2))) {
				added = u"&story="_q + storyMatch->captured(1);
			} else if (const auto albumMatch = regex_match(u"^/a/(\\d+)(/?\\?|/?$)"_q, usernameMatch->captured(2))) {
				added = u"&album="_q + albumMatch->captured(1);
			} else if (const auto collectionMatch = regex_match(u"^/c/(\\d+)(/?\\?|/?$)"_q, usernameMatch->captured(2))) {
				added = u"&collection="_q + collectionMatch->captured(1);
			} else if (const auto appNameMatch = regex_match(u"^/([a-zA-Z0-9\\.\\_\\-]+)(/?\\?|/?$)"_q, usernameMatch->captured(2))) {
				added = u"&appname="_q + appNameMatch->captured(1);
			}
			return base + added + (params.isEmpty() ? QString() : '&' + params);
		}
	}
	return url;
}

} // namespace

QString TryConvertUrlToLocal(QString url) {
	return ConvertLegacyUrlToLocal(std::move(url));
}

QString TryConvertUrlToLocal(
		QString url,
		const QString &internalLinksDomain,
		bool hasPinnedServer) {
	if (hasPinnedServer && url.size() <= 8192) {
		if (const auto remapped = CustomOriginUrlAsTelegramUrl(
				url,
				internalLinksDomain)) {
			const auto local = ConvertLegacyUrlToLocal(*remapped);
			return local.startsWith(u"tg://"_q, Qt::CaseInsensitive)
				? WithoutAccountIndex(local)
				: std::move(url);
		}
	}
	return ConvertLegacyUrlToLocal(std::move(url));
}

} // namespace Core
