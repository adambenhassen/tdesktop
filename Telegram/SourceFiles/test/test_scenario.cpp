/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#ifdef _DEBUG

#include "test/test_runner.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "core/update_checker.h"
#include "core/update_policy.h"
#include "intro/intro_server_discovery.h"
#include "lang/lang_cloud_manager.h"
#include "lang/lang_instance.h"
#include "main/main_account.h"
#include "main/main_app_config.h"
#include "main/main_domain.h"
#include "mtproto/mtproto_server_discovery.h"
#include "mtproto/mtproto_server_enrollment.h"
#include "storage/storage_account.h"
#include "storage/storage_domain.h"
#include "test/test_log.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QSslError>
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QTcpSocket>

#include <algorithm>
#include <memory>
#include <optional>
#include <utility>

namespace Test {
namespace {

constexpr auto kPublicHost = "public.example";
constexpr auto kPublicOrigin
	= "https://public.example/.well-known/telegramd/client";
constexpr auto kPublicFailureHost = "public-failure.invalid";
constexpr auto kPublicFailureOrigin
	= "https://public-failure.invalid/.well-known/telegramd/client";
constexpr auto kDiscoveryDestination = "127.0.0.1:19081";
constexpr auto kPinnedHost = "127.0.0.1";
constexpr auto kPinnedDestination = "127.0.0.1:19082";
constexpr auto kPinnedPort = quint16(19082);
constexpr auto kFailureDestination = "127.0.0.1:19083";
constexpr auto kProxyHost = "127.0.0.1";
constexpr auto kProxyPort = quint16(19080);

[[nodiscard]] bool IsKnownCase(const QString &name) {
	return name == u"fresh-empty"_q
		|| name == u"malformed-selection"_q
		|| name == u"canceled-selection"_q
		|| name == u"failed-selection"_q
		|| name == u"partial-selection"_q
		|| name == u"timed-out-selection"_q
		|| name == u"public-selection"_q
		|| name == u"public-failure"_q
		|| name == u"local-preflight"_q
		|| name == u"pinned-endpoint"_q
		|| name == u"restart-pinned"_q
		|| name == u"multiple-account-isolation"_q
		|| name == u"proxy-intermediary"_q
		|| name == u"background-refresh"_q
		|| name == u"selected-endpoint-failure"_q
		|| name == u"late-callback"_q;
}

[[nodiscard]] QString HostInfoErrorName(QHostInfo::HostInfoError error) {
	switch (error) {
	case QHostInfo::NoError:
		return u"NoError"_q;
	case QHostInfo::HostNotFound:
		return u"HostNotFound"_q;
	case QHostInfo::UnknownError:
		return u"UnknownError"_q;
	}
	return u"UnknownError"_q;
}

const char kRsa2048Spki[] = "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n\
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n\
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n\
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n\
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n\
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n\
-----END RSA PUBLIC KEY-----";

[[nodiscard]] MTP::details::RSAPublicKey TestKey() {
	return MTP::details::RSAPublicKey(bytes::make_span(
		kRsa2048Spki,
		sizeof(kRsa2048Spki) - 1));
}

void AppendBigEndian(QByteArray &target, quint32 value) {
	target.append(char(value >> 24));
	target.append(char(value >> 16));
	target.append(char(value >> 8));
	target.append(char(value));
}

void AppendBigEndian(QByteArray &target, quint16 value) {
	target.append(char(value >> 8));
	target.append(char(value));
}

[[nodiscard]] QByteArray LocalResponse(const QByteArray &nonce) {
	const auto der = TestKey().getSubjectPublicKeyInfo();
	auto response = QByteArray("telegramd-key-r1", 16) + nonce;
	AppendBigEndian(response, quint32(6 + der.size()));
	AppendBigEndian(response, quint32(2));
	AppendBigEndian(response, quint16(der.size()));
	response += QByteArray(
		reinterpret_cast<const char *>(der.data()),
		int(der.size()));
	return response;
}

struct NetworkCaseState final {
	~NetworkCaseState() {
		stop();
	}

	void stop() {
		if (_account && !_done) {
			_account->mtp().stopForServerEnrollment();
			_account = nullptr;
		}
		if (_lookupId >= 0) {
			QHostInfo::abortHostLookup(_lookupId);
			_lookupId = -1;
		}
		if (_reply) {
			_reply->abort();
			_reply = nullptr;
		}
		if (_network) {
			_network.reset();
		}
		if (_discovery && _discovery->running()) {
			_discovery->cancel();
		}
		_discovery.reset();
		_discoveryAttempt.reset();
		if (_updateChecker) {
			_updateChecker->stop();
			_updateChecker.reset();
		}
		if (_localPeer) {
			_localPeer->abort();
			_localPeer = nullptr;
		}
		if (_localServer) {
			_localServer->close();
		}
		if (_proxySettingsSaved) {
			Core::App().setCurrentProxy(
				_originalProxy,
				_originalProxySettings);
			_proxySettingsSaved = false;
		}
	}

	void settle() {
		if (_done) {
			return;
		}
		if (_account) {
			_account->mtp().stopForServerEnrollment();
			_account = nullptr;
		}
		_done = true;
		stop();
	}

	[[nodiscard]] Main::Account *accountForCase() {
		auto &domain = Core::App().domain();
		if (!domain.started()) {
			Fail(u"test account domain is started"_q);
			return nullptr;
		}
		if (!domain.accounts().empty()) {
			return domain.accounts().front().account.get();
		}
		return &*domain.add(MTP::Environment::Production);
	}

	[[nodiscard]] bool commitResult(
			Main::Account &account,
			const MTP::ServerDiscoveryResult &result,
			Fn<void()> resume) {
		const auto endpoint = MTP::CheckServerSelection(result.endpoint);
		if (!result.valid() || !endpoint
			|| endpoint.policy != MTP::ServerDiscoveryPolicy::LocalDirect) {
			return false;
		}
		const auto connectionHost = result.resolvedAddress.isEmpty()
			? endpoint.host
			: result.resolvedAddress;
		const auto connection = MTP::CheckServerSelection(
			connectionHost + u":"_q + QString::number(endpoint.operationalPort));
		if (!connection || connection.policy != MTP::ServerDiscoveryPolicy::LocalDirect) {
			return false;
		}
		const auto key = std::make_shared<MTP::details::RSAPublicKey>(result.key);
		const auto server = MTP::CustomServer{
			.dcId = result.dcId,
			.ip = connection.host.toStdString(),
			.port = endpoint.operationalPort,
			.ipv6 = connection.ipv6,
			.key = key,
			.serverSelection = endpoint.normalizedSelection.toStdString(),
			.discoveryPolicy = result.policy,
			.discoveryOrigin = result.origin.toStdString(),
		};
		const auto previousOptions = account.mtp().dcOptions().serialize();
		const auto previousWasBlocked = account.mtp().dcOptions().blocked();
		const auto previousWasUnenrolled = account.mtp().dcOptions().unenrolled();
		return MTP::CommitServerEnrollment(
			[&] {
				return account.mtp().dcOptions().setCustomServer(server);
			},
			[&] {
				return account.local().writeMtpConfig(true);
			},
			std::move(resume),
			[&] {
				if (previousWasBlocked) {
					account.mtp().dcOptions().constructBlocked();
				} else if (previousWasUnenrolled) {
					account.mtp().dcOptions().constructUnenrolled();
				} else if (!account.mtp().dcOptions().constructFromSerialized(
						previousOptions)) {
					account.mtp().dcOptions().constructBlocked();
				}
			});
	}

	void startPublic(bool failure) {
		const auto host = failure
			? QString::fromLatin1(kPublicFailureHost)
			: QString::fromLatin1(kPublicHost);
		const auto origin = failure
			? QString::fromLatin1(kPublicFailureOrigin)
			: QString::fromLatin1(kPublicOrigin);
		const auto selection = MTP::CheckServerSelection(host);
		Check(
			selection
				&& selection.policy == MTP::ServerDiscoveryPolicy::PublicHttps,
			u"public selection uses HTTPS discovery"_q);
		Check(
			MTP::PublicDiscoveryUrl(selection) == origin,
			u"public selection records its normalized origin"_q);
		const auto fixture = qEnvironmentVariable(
			"TDESKTOP_NETWORK_TRACE_PUBLIC_FIXTURE");
		const auto fixtureAddress = qEnvironmentVariable(
			"TDESKTOP_NETWORK_TRACE_PUBLIC_ADDRESS");
		const auto fixtureProxy = qEnvironmentVariable(
			"TDESKTOP_NETWORK_TRACE_PUBLIC_PROXY");
		Check(
			fixture == u"public-discovery.json"_q,
			u"public selection uses the checked-in HTTPS fixture"_q);
		const auto address = QHostAddress(fixtureAddress);
		const auto proxy = MTP::CheckServerSelection(fixtureProxy);
		Check(
			address.protocol() == QAbstractSocket::IPv4Protocol
				&& fixtureAddress == address.toString(),
			u"public fixture address is canonical"_q);
		Check(
			proxy
				&& proxy.policy == MTP::ServerDiscoveryPolicy::LocalDirect,
			u"public fixture proxy is local"_q);
		if (address.isNull() || !proxy) {
			settle();
			return;
		}
		_publicFailure = failure;
		_network = std::make_unique<QNetworkAccessManager>();
		auto networkProxy = QNetworkProxy(
			QNetworkProxy::Socks5Proxy,
			proxy.host,
			quint16(proxy.operationalPort));
		networkProxy.setCapabilities(
			QNetworkProxy::TunnelingCapability
			| QNetworkProxy::HostNameLookupCapability);
		_network->setProxy(networkProxy);
		auto request = QNetworkRequest(QUrl(
			MTP::PublicDiscoveryUrl(selection)));
		MTP::ConfigurePublicDiscoveryRequest(request);
		_reply = _network->get(request);
		QObject::connect(
			_reply.data(),
			&QNetworkReply::finished,
			[shared = shared_from_this(), selection] {
				if (shared->_done || !shared->_reply) {
					return;
				}
				const auto error = shared->_reply->error();
				const auto status = shared->_reply->attribute(
					QNetworkRequest::HttpStatusCodeAttribute).toInt();
				const auto body = shared->_reply->readAll();
				const auto result = MTP::ParsePublicDiscoveryResponse(
					selection,
					body);
				shared->_publicReplyFinished = true;
				Check(
					shared->_publicFailure
						? (!result.valid()
							|| error != QNetworkReply::NoError
							|| status != 200)
						: (result.valid()
							&& error == QNetworkReply::NoError
							&& status == 200),
					shared->_publicFailure
						? u"public HTTPS failure is terminal"_q
						: u"public HTTPS discovery response is valid"_q);
				Note(u"public HTTPS discovery completed: status=%1 error=%2 valid=%3"_q.arg(
					QString::number(status),
					QString::number(int(error)),
					result.valid() ? u"true"_q : u"false"_q));
				shared->_reply->deleteLater();
				shared->_reply = nullptr;
				shared->maybeFinishPublic();
			});
		QObject::connect(
			_reply.data(),
			&QNetworkReply::sslErrors,
			[reply = _reply.data()](const QList<QSslError> &) {
				reply->ignoreSslErrors();
			});
		_lookupId = QHostInfo::lookupHost(
			fixtureAddress,
			QCoreApplication::instance(),
			[shared = shared_from_this(), host, fixtureAddress](
					const QHostInfo &info) {
				if (shared->_done) {
					return;
				}
				shared->_lookupId = -1;
				const auto addresses = info.addresses();
				shared->_resolutionObserved = true;
				Check(
					info.error() == QHostInfo::NoError
						&& std::any_of(
							addresses.cbegin(),
							addresses.cend(),
							[fixtureAddress](const QHostAddress &address) {
								return address.toString() == fixtureAddress;
							}),
					u"public selection observes the fixture resolver callback"_q);
				Note(u"public resolver completed: host=%1 error=%2 addresses=%3"_q.arg(
					host,
					HostInfoErrorName(info.error()),
					QString::number(addresses.size())));
				shared->maybeFinishPublic();
			});
		if (_lookupId < 0) {
			Fail(u"start public resolver"_q);
			_resolutionObserved = false;
			maybeFinishPublic();
		}
	}

	void maybeFinishPublic() {
		if (_publicReplyFinished && _resolutionObserved) {
			QTimer::singleShot(0, [shared = shared_from_this()] {
				if (shared->_publicReplyFinished && shared->_resolutionObserved) {
					shared->settle();
				}
			});
		}
	}

	void listenLocal(quint16 port) {
		_localServer = std::make_unique<QTcpServer>();
		QObject::connect(
			_localServer.get(),
			&QTcpServer::newConnection,
			[shared = shared_from_this()] { shared->acceptLocal(); });
		if (!_localServer->listen(
				QHostAddress(QString::fromLatin1(kPinnedHost)),
				port)) {
			Fail(u"start local discovery observer"_q);
			settle();
		}
	}

	void acceptLocal() {
		if (!_localServer) {
			return;
		}
		while (_localServer->hasPendingConnections()) {
			const auto peer = QPointer<QTcpSocket>(
				_localServer->nextPendingConnection());
			_localPeer = peer;
			_localRequest.clear();
			QObject::connect(
				peer.data(),
				&QTcpSocket::readyRead,
				[shared = shared_from_this(), peer] {
					shared->localReadyRead(peer);
				});
		}
	}

	void localReadyRead(QPointer<QTcpSocket> peer) {
		if (!peer || _done) {
			return;
		}
		const auto data = peer->readAll();
		if (_localRequest.isEmpty()
			&& !data.startsWith(QByteArray("telegramd-key-v1", 16))) {
			return;
		}
		_localRequest += data;
		if (_localRequest.size() < 48) {
			return;
		}
		if (_holdResponse) {
			return;
		}
		const auto nonce = _localRequest.mid(16, 32);
		if (_partialResponse) {
			peer->write(QByteArray("telegramd-key-r1", 16));
		} else {
			peer->write(LocalResponse(nonce));
		}
		peer->flush();
		_localRequest.clear();
		peer->disconnectFromHost();
	}

	void startLocalDiscovery(
			const QString &endpoint,
			bool serve,
			bool holdResponse,
			bool partialResponse,
			bool allowFailure,
			Fn<void(MTP::ServerDiscoveryResult)> finished) {
		_selection = MTP::CheckServerSelection(endpoint);
		Check(
			_selection
				&& _selection.policy == MTP::ServerDiscoveryPolicy::LocalDirect,
			u"local case selects the direct discovery policy"_q);
		if (!_selection) {
			settle();
			return;
		}
		_holdResponse = holdResponse;
		_partialResponse = partialResponse;
		_expectDiscoveryFailure = allowFailure;
		if (serve) {
			listenLocal(quint16(_selection.operationalPort));
			if (_done) {
				return;
			}
		}
		_discovery = std::make_unique<Intro::details::ServerWidgetDiscovery>(
			QCoreApplication::instance());
		_discoveryAttempt = _discovery->acquireAttempt();
		Check(
			_discoveryAttempt.has_value()
				&& _discoveryAttempt->token.has_value(),
			u"live discovery acquires its attempt token"_q);
		if (!_discoveryAttempt.has_value()
			|| !_discoveryAttempt->token.has_value()) {
			settle();
			return;
		}
		_discoveryNonce = QByteArray(32, 'N');
		const auto addresses = QList<QHostAddress>{ QHostAddress(
			_selection.host) };
		_discovery->start(
			_selection,
			_discoveryNonce,
			addresses,
			{
				.finished = [shared = shared_from_this(), finished = std::move(finished)](
						MTP::ServerDiscoveryResult result) mutable {
					++shared->_discoveryCallbacks;
					Check(
						result.valid() && !result.resolvedAddress.isEmpty(),
						u"live discovery reports the peer it resolved"_q);
					if (result.valid()) {
						QTimer::singleShot(
							0,
							[shared, finished = std::move(finished), result = std::move(result)]
							() mutable {
								if (!shared->_done) {
									finished(std::move(result));
								}
							});
					} else {
						QTimer::singleShot(0, [shared] { shared->settle(); });
					}
				},
				.failed = [shared = shared_from_this()](bool connectionFailure) {
					++shared->_discoveryCallbacks;
					Check(
						shared->_expectDiscoveryFailure,
						u"live discovery failure is handled by the selected case"_q);
					Note(u"live discovery failed: connection=%1"_q.arg(
						connectionFailure ? u"true"_q : u"false"_q));
					QTimer::singleShot(0, [shared] { shared->settle(); });
				},
				.candidateStarted = [shared = shared_from_this()] {
					Note(u"live discovery submitted a bounded candidate"_q);
				},
			});
	}

	void prepareNetworkFreeDiscovery(const QString &endpoint) {
		_selection = MTP::CheckServerSelection(endpoint);
		Check(
			_selection
				&& _selection.policy == MTP::ServerDiscoveryPolicy::LocalDirect,
			u"network-free selection uses the direct policy"_q);
		if (!_selection) {
			settle();
			return;
		}
		_discovery = std::make_unique<Intro::details::ServerWidgetDiscovery>(
			QCoreApplication::instance());
		_discoveryAttempt = _discovery->acquireAttempt();
		Check(
			_discoveryAttempt.has_value()
				&& _discoveryAttempt->token.has_value(),
			u"network-free discovery acquires its attempt token"_q);
		_discoveryNonce = QByteArray(32, 'N');
		_preselectionFailure = false;
	}

	void startCanceledSelection() {
		prepareNetworkFreeDiscovery(QString::fromLatin1(kDiscoveryDestination));
		_discovery->cancel();
		Check(!_discovery->running(), u"canceled discovery is stopped"_q);
		Check(
			_discoveryCallbacks == 0,
			u"canceled discovery has no completion callback"_q);
		Note(u"canceled selection completed before network discovery"_q);
		settle();
	}

	void startFailedSelection() {
		prepareNetworkFreeDiscovery(QString::fromLatin1(kFailureDestination));
		_expectDiscoveryFailure = true;
		_discovery->start(
			_selection,
			_discoveryNonce,
			{},
			{
				.failed = [shared = shared_from_this()](bool connectionFailure) {
					++shared->_discoveryCallbacks;
					shared->_preselectionFailure = true;
					Check(
						connectionFailure,
						u"failed selection reports a connection failure"_q);
				},
			});
		Check(
			_preselectionFailure,
			u"failed selection completes without a socket"_q);
		settle();
	}

	void startPartialSelection() {
		prepareNetworkFreeDiscovery(QString::fromLatin1(kDiscoveryDestination));
		const auto partial = QByteArray("telegramd-key-r1", 16);
		Check(
			!MTP::IsCompleteLocalDiscoveryResponse(partial),
			u"partial discovery response is rejected"_q);
		Check(
			!MTP::ParseLocalDiscoveryResponse(
				_selection,
				_discoveryNonce,
				partial).valid(),
			u"partial discovery result is invalid"_q);
		Note(u"partial selection completed before network discovery"_q);
		settle();
	}

	void startTimedOutSelection() {
		prepareNetworkFreeDiscovery(QString::fromLatin1(kDiscoveryDestination));
		_discovery->start(
			_selection,
			_discoveryNonce,
			{},
			{
				.failed = [shared = shared_from_this()](bool) {
					++shared->_discoveryCallbacks;
					shared->_preselectionFailure = true;
				},
			});
		Check(
			_preselectionFailure && !_discovery->timeout(),
			u"timed-out selection stops without a socket"_q);
		settle();
	}

	void startLateCallback() {
		prepareNetworkFreeDiscovery(QString::fromLatin1(kDiscoveryDestination));
		_discovery->start(
			_selection,
			_discoveryNonce,
			{},
			{
				.failed = [shared = shared_from_this()](bool) {
					++shared->_discoveryCallbacks;
					shared->_preselectionFailure = true;
				},
			});
		_discovery->cancel();
		Check(
			_preselectionFailure && _discoveryCallbacks == 1,
			u"late discovery callback is discarded after cancellation"_q);
		Note(u"late callback completed before network discovery"_q);
		settle();
	}

	void startLocalPreflight() {
		startLocalDiscovery(
			QString::fromLatin1(kDiscoveryDestination),
			true,
			false,
			false,
			false,
			[shared = shared_from_this()](MTP::ServerDiscoveryResult result) {
				Check(
					result.endpoint == QString::fromLatin1(kDiscoveryDestination),
					u"local preflight keeps the selected endpoint"_q);
				shared->settle();
			});
	}

	void startPinnedEndpoint() {
		_account = accountForCase();
		if (!_account) {
			settle();
			return;
		}
		startLocalDiscovery(
			QString::fromLatin1(kPinnedDestination),
			true,
			false,
			false,
			false,
			[shared = shared_from_this()](MTP::ServerDiscoveryResult result) {
				const auto committed = shared->commitResult(
					*shared->_account,
					result,
					[shared] { shared->_account->mtp().resume(); });
				Check(committed, u"pinned endpoint commits through enrollment"_q);
				if (committed) {
					QTimer::singleShot(1000, [shared] { shared->settle(); });
				} else {
					shared->settle();
				}
			});
	}

	void startRestartPinned() {
		_account = accountForCase();
		if (!_account) {
			settle();
			return;
		}
		startLocalDiscovery(
			QString::fromLatin1(kPinnedDestination),
			true,
			false,
			false,
			false,
			[shared = shared_from_this()](MTP::ServerDiscoveryResult result) {
				const auto committed = shared->commitResult(
					*shared->_account,
					result,
					nullptr);
				Check(committed, u"restart case durably commits the pin"_q);
				if (!committed) {
					shared->settle();
					return;
				}
				auto &domain = Core::App().domain();
				domain.finish();
				Check(
					domain.start(QByteArray()) == Storage::StartResult::Success,
					u"restart reloads the account domain"_q);
				shared->_account = nullptr;
				for (const auto &[index, account] : domain.accounts()) {
					if (account->mtp().dcOptions().hasCustomServer()) {
						shared->_account = account.get();
						break;
					}
				}
				Check(
					shared->_account != nullptr,
					u"restart restores the account's custom server"_q);
				if (shared->_account) {
					shared->_account->mtp().resume();
				}
				QTimer::singleShot(1000, [shared] { shared->settle(); });
			});
	}

	void startMultipleAccountIsolation() {
		_account = accountForCase();
		if (!_account) {
			settle();
			return;
		}
		auto &domain = Core::App().domain();
		const auto other = &*domain.add(MTP::Environment::Production);
		startLocalDiscovery(
			QString::fromLatin1(kPinnedDestination),
			true,
			false,
			false,
			false,
			[shared = shared_from_this(), other, domainPtr = &domain](
					MTP::ServerDiscoveryResult result) {
				const auto committed = shared->commitResult(
					*shared->_account,
					result,
					nullptr);
				Check(committed, u"account A commits its own enrollment"_q);
				Check(
					!other->mtp().dcOptions().hasCustomServer(),
					u"account B has no inherited custom server"_q);
				Check(
					other->mtp().dcOptions().unenrolled(),
					u"account B remains independently unenrolled"_q);
				domainPtr->activate(not_null{ other });
				other->mtp().resume();
				other->mtp().requestConfigIfOld();
				QTimer::singleShot(100, [shared, other, domainPtr] {
					Check(
						other->mtp().dcOptions().unenrolled()
							&& !other->mtp().dcOptions().hasCustomServer(),
						u"account B request remains network-gated"_q);
					domainPtr->activate(not_null{ shared->_account });
					shared->_account->mtp().resume();
					QTimer::singleShot(
						1000,
						[shared] { shared->settle(); });
				});
			});
	}

	void startSelectedEndpointFailure() {
		_account = accountForCase();
		if (!_account) {
			settle();
			return;
		}
		startLocalDiscovery(
			QString::fromLatin1(kFailureDestination),
			true,
			false,
			false,
			false,
			[shared = shared_from_this()](MTP::ServerDiscoveryResult result) {
				const auto committed = shared->commitResult(
					*shared->_account,
					result,
					[shared] {
						if (shared->_localServer) {
							shared->_localServer->close();
						}
						shared->_account->mtp().resume();
					});
				Check(committed, u"failed endpoint is committed before connect"_q);
				QTimer::singleShot(2000, [shared] {
					const auto &options = shared->_account->mtp().dcOptions();
					Check(
						options.hasCustomServer()
							&& options.refusesProductionFallback(),
						u"selected endpoint failure suppresses production fallback"_q);
					shared->settle();
				});
			});
	}

	void startBackgroundRefresh() {
		_account = accountForCase();
		if (!_account) {
			settle();
			return;
		}
		startLocalDiscovery(
			QString::fromLatin1(kPinnedDestination),
			true,
			false,
			false,
			false,
			[shared = shared_from_this()](MTP::ServerDiscoveryResult result) {
				const auto committed = shared->commitResult(
					*shared->_account,
					result,
					[shared] { shared->_account->mtp().resume(); });
				Check(committed, u"background case pins its account first"_q);
				shared->_account->appConfig().start();
				shared->_account->appConfig().refresh(true);
				const auto language = Core::App().langpack().cloudLangCode(
					Lang::Pack::Current);
				if (!language.isEmpty()) {
					if (const auto manager = Core::App().langCloudManager()) {
						manager->requestLangPackDifference(language);
					}
				}
				shared->_account->mtp().requestConfigIfOld();
				shared->_account->mtp().requestCDNConfig();
				shared->_updateChecker = std::make_unique<Core::UpdateChecker>();
				shared->_updateChecker->test();
				Note(u"background refresh invoked app-config and update-check paths"_q);
				QTimer::singleShot(1000, [shared] {
					Check(
						shared->_updateChecker != nullptr,
						u"background update checker was created"_q);
					Check(
						!Core::UpdateNetworkAllowed(
							Core::UpdateEntryPoint::Automatic)
							&& !Core::UpdateNetworkAllowed(
								Core::UpdateEntryPoint::Manual),
						u"untrusted update origins remain network-disabled"_q);
					shared->settle();
				});
			});
	}

	void startProxy() {
		_account = accountForCase();
		if (!_account) {
			settle();
			return;
		}
		startLocalDiscovery(
			QString::fromLatin1(kPinnedDestination),
			true,
			false,
			false,
			false,
			[shared = shared_from_this()](MTP::ServerDiscoveryResult result) {
				auto &settings = Core::App().settings().proxy();
				shared->_originalProxy = settings.selected();
				shared->_originalProxySettings = settings.settings();
				shared->_proxySettingsSaved = true;
				auto proxy = MTP::ProxyData();
				proxy.type = MTP::ProxyData::Type::Socks5;
				proxy.host = QString::fromLatin1(kProxyHost);
				proxy.port = kProxyPort;
				Core::App().setCurrentProxy(
					proxy,
					MTP::ProxyData::Settings::Enabled);
				const auto configured = settings.selected();
				const auto proxyConfigured = settings.isEnabled()
					&& configured.type == MTP::ProxyData::Type::Socks5
					&& configured.host == QString::fromLatin1(kProxyHost)
					&& configured.port == kProxyPort;
				Check(
					proxyConfigured,
					u"account transport uses the bounded SOCKS5 proxy"_q);
				if (!proxyConfigured) {
					shared->settle();
					return;
				}
				const auto committed = shared->commitResult(
					*shared->_account,
					result,
					[shared] { shared->_account->mtp().resume(); });
				Check(committed, u"proxy case commits its endpoint before resume"_q);
				if (!committed) {
					shared->settle();
					return;
				}
				QTimer::singleShot(1500, [shared] { shared->settle(); });
			});
	}

	[[nodiscard]] bool done() const {
		return _done;
	}

	[[nodiscard]] bool evidenceWritten() const {
		return _resolutionObserved;
	}

	std::shared_ptr<NetworkCaseState> shared_from_this() {
		return _self.lock();
	}

	void setSelf(const std::shared_ptr<NetworkCaseState> &self) {
		_self = self;
	}

	std::unique_ptr<QTcpServer> _localServer;
	std::unique_ptr<Intro::details::ServerWidgetDiscovery> _discovery;
	std::unique_ptr<QNetworkAccessManager> _network;
	std::unique_ptr<Core::UpdateChecker> _updateChecker;
	QPointer<QTcpSocket> _localPeer;
	QPointer<QNetworkReply> _reply;
	std::weak_ptr<NetworkCaseState> _self;
	std::optional<Intro::details::ServerWidgetDiscovery::Attempt>
		_discoveryAttempt;
	Main::Account *_account = nullptr;
	MTP::ServerSelectionCheck _selection;
	QByteArray _discoveryNonce;
	QByteArray _localRequest;
	MTP::ProxyData _originalProxy;
	MTP::ProxyData::Settings _originalProxySettings =
		MTP::ProxyData::Settings::System;
	int _lookupId = -1;
	int _discoveryCallbacks = 0;
	bool _done = false;
	bool _publicFailure = false;
	bool _publicReplyFinished = false;
	bool _expectDiscoveryFailure = false;
	bool _holdResponse = false;
	bool _partialResponse = false;
	bool _resolutionObserved = false;
	bool _proxySettingsSaved = false;
	bool _preselectionFailure = false;
};

[[nodiscard]] std::shared_ptr<NetworkCaseState> MakeState() {
	const auto state = std::make_shared<NetworkCaseState>();
	state->setSelf(state);
	return state;
}

void AddNoNetworkCase(
		not_null<Runner*> runner,
		const QString &name,
		Fn<void()> action) {
	auto complete = std::make_shared<bool>(false);
	runner->add({
		.name = name,
		.run = [complete, action = std::move(action)] {
			action();
			*complete = true;
		},
		.until = [complete] { return *complete; },
		.timeout = crl::time(1000),
	});
}

void AddNetworkCase(
		not_null<Runner*> runner,
		const QString &name,
		const std::shared_ptr<NetworkCaseState> &state,
		Fn<void()> action) {
	runner->add({
		.name = u"run network trace case: %1"_q.arg(name),
		.run = std::move(action),
		.until = [state] { return state->done(); },
		.then = [state, name] {
			Check(state->done(), u"network trace case settled"_q);
			if (name == u"public-selection"_q
				|| name == u"public-failure"_q) {
				Check(
					state->evidenceWritten(),
					u"public resolution evidence was written"_q);
			}
		},
		.timeout = crl::time(3000),
	});
}

} // namespace

void SetupScenario(not_null<Runner*> runner) {
	const auto name = qEnvironmentVariable("TDESKTOP_NETWORK_TRACE_CASE");
	if (name.isEmpty()) {
		return;
	}
	if (!IsKnownCase(name)) {
		AddNoNetworkCase(runner, u"reject unknown network trace case"_q, [=] {
			Fail(
				u"network trace case selector"_q,
				u"unknown case: %1"_q.arg(name));
		});
		return;
	}

	if (name == u"fresh-empty"_q) {
		AddNoNetworkCase(runner, name, [] {
			Check(
				!MTP::CheckServerSelection(QString()).valid(),
				u"empty storage has no selected server"_q);
		});
	} else if (name == u"malformed-selection"_q) {
		AddNoNetworkCase(runner, name, [] {
			for (const auto &value : {
				u"not a server"_q,
				u"[2001:db8::1"_q,
				u"localhost"_q,
			}) {
				Check(
					!MTP::CheckServerSelection(value),
					u"malformed selection has no network policy"_q);
			}
		});
	} else if (name == u"canceled-selection"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startCanceledSelection();
		});
	} else if (name == u"failed-selection"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startFailedSelection();
		});
	} else if (name == u"partial-selection"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startPartialSelection();
		});
	} else if (name == u"timed-out-selection"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startTimedOutSelection();
		});
	} else if (name == u"late-callback"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startLateCallback();
		});
	} else if (name == u"public-selection"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startPublic(false);
		});
	} else if (name == u"public-failure"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startPublic(true);
		});
	} else if (name == u"local-preflight"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startLocalPreflight();
		});
	} else if (name == u"pinned-endpoint"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startPinnedEndpoint();
		});
	} else if (name == u"restart-pinned"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startRestartPinned();
		});
	} else if (name == u"multiple-account-isolation"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startMultipleAccountIsolation();
		});
	} else if (name == u"proxy-intermediary"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startProxy();
		});
	} else if (name == u"background-refresh"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startBackgroundRefresh();
		});
	} else if (name == u"selected-endpoint-failure"_q) {
		const auto state = MakeState();
		AddNetworkCase(runner, name, state, [state] {
			state->startSelectedEndpointFailure();
		});
	}
}

} // namespace Test

#endif // _DEBUG
