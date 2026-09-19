/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#ifdef _DEBUG

#include "test/test_runner.h"

#include "core/application.h"
#include "core/update_checker.h"
#include "intro/intro_server_discovery.h"
#include "main/main_account.h"
#include "main/main_app_config.h"
#include "main/main_domain.h"
#include "mtproto/mtproto_server_discovery.h"
#include "mtproto/mtproto_server_enrollment.h"
#include "storage/storage_account.h"
#include "storage/storage_domain.h"
#include "test/test_log.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QNetworkProxy>
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

[[nodiscard]] QString EvidenceFile(const QString &name) {
	return EvidenceDir() + name;
}

[[nodiscard]] QString Endpoint(
		const QHostAddress &address,
		quint16 port) {
	const auto host = address.toString();
	return (address.protocol() == QAbstractSocket::IPv6Protocol
			? (u"["_q + host + u"]"_q)
			: host)
		+ u":"_q
		+ QString::number(port);
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

[[nodiscard]] bool WriteResolutionEvidence(
		const QString &host,
		const QString &origin,
		const QHostInfo &info,
		quint16 port) {
	auto addresses = QJsonArray();
	auto destinations = QJsonArray();
	for (const auto &address : info.addresses()) {
		if (address.protocol() != QAbstractSocket::IPv4Protocol
			&& address.protocol() != QAbstractSocket::IPv6Protocol) {
			continue;
		}
		addresses.append(address.toString());
		destinations.append(Endpoint(address, port));
	}
	auto object = QJsonObject();
	object.insert(u"origin"_q, origin);
	object.insert(u"host"_q, host);
	object.insert(u"error"_q, HostInfoErrorName(info.error()));
	object.insert(u"addresses"_q, addresses);
	object.insert(u"destinations"_q, destinations);
	auto file = QFile(EvidenceFile(u"network-resolution.json"_q));
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
		Fail(
			u"write public resolution evidence"_q,
			u"could not open network-resolution.json"_q);
		return false;
	}
	const auto data = QJsonDocument(object).toJson(QJsonDocument::Compact);
	if (file.write(data) != data.size() || file.write("\n") != 1) {
		Fail(
			u"write public resolution evidence"_q,
			u"could not write network-resolution.json"_q);
		return false;
	}
	file.flush();
	return true;
}

[[nodiscard]] std::optional<QString> SocksConnectTarget(
		const QByteArray &request) {
	if (request.size() != 10
		|| request[0] != char(0x05)
		|| request[1] != char(0x01)
		|| request[2] != char(0x00)
		|| request[3] != char(0x01)) {
		return std::nullopt;
	}
	const auto target = QStringLiteral("%1.%2.%3.%4:%5")
		.arg(uchar(request[4]))
		.arg(uchar(request[5]))
		.arg(uchar(request[6]))
		.arg(uchar(request[7]))
		.arg((quint16(uchar(request[8])) << 8) | uchar(request[9]));
	return target;
}

[[nodiscard]] bool WriteProxyTargetEvidence(const QString &target) {
	const auto path = qEnvironmentVariable("TDESKTOP_PROXY_ASSERTION_FILE");
	if (path.isEmpty()) {
		Fail(
			u"write proxy target evidence"_q,
			u"TDESKTOP_PROXY_ASSERTION_FILE is unset"_q);
		return false;
	}
	auto object = QJsonObject();
	object.insert(u"protocol"_q, u"SOCKS5"_q);
	object.insert(u"version"_q, 5);
	object.insert(u"command"_q, u"CONNECT"_q);
	object.insert(u"target"_q, target);
	object.insert(u"observed"_q, true);
	auto file = QFile(path);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
		Fail(
			u"write proxy target evidence"_q,
			u"could not open the assertion file"_q);
		return false;
	}
	const auto data = QJsonDocument(object).toJson(QJsonDocument::Compact);
	if (file.write(data) != data.size() || file.write("\n") != 1) {
		Fail(
			u"write proxy target evidence"_q,
			u"could not write the assertion file"_q);
		return false;
	}
	file.flush();
	return true;
}

struct NetworkCaseState final {
	~NetworkCaseState() {
		stop();
	}

	void stop() {
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
		closeSocket();
		if (_proxyPeer) {
			_proxyPeer->abort();
			_proxyPeer = nullptr;
		}
		if (_proxyServer) {
			_proxyServer->close();
		}
	}

	void closeSocket() {
		if (_socket) {
			QObject::disconnect(_socket.get(), nullptr, nullptr, nullptr);
			_socket->abort();
			_socket.reset();
		}
	}

	void settle() {
		if (_done) {
			return;
		}
		_done = true;
		_socketFinished = nullptr;
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
		_publicFailure = failure;
		_network = std::make_unique<QNetworkAccessManager>();
		_network->setProxy(QNetworkProxy::NoProxy);
		auto request = QNetworkRequest(QUrl(MTP::PublicDiscoveryUrl(selection)));
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
				const auto body = shared->_reply->readAll();
				const auto result = MTP::ParsePublicDiscoveryResponse(
					selection,
					body);
				shared->_publicReplyFinished = true;
				Check(
					shared->_publicFailure
						? (!result.valid() || error != QNetworkReply::NoError)
						: (result.valid() && error == QNetworkReply::NoError),
					shared->_publicFailure
						? u"public HTTPS failure is terminal"_q
						: u"public HTTPS discovery response is valid"_q);
				Note(u"public HTTPS discovery completed: error=%1 valid=%2"_q.arg(
					QString::number(int(error)),
					result.valid() ? u"true"_q : u"false"_q));
				shared->_reply->deleteLater();
				shared->_reply = nullptr;
				shared->maybeFinishPublic();
			});
		_lookupId = QHostInfo::lookupHost(
			host,
			QCoreApplication::instance(),
			[shared = shared_from_this(), host, origin](const QHostInfo &info) {
				if (shared->_done) {
					return;
				}
				shared->_lookupId = -1;
				const auto addresses = info.addresses();
				shared->_resolutionWritten = WriteResolutionEvidence(
					host,
					origin,
					info,
					443);
				Check(
					shared->_publicFailure
						? info.error() != QHostInfo::NoError
						: (info.error() == QHostInfo::NoError
							&& std::any_of(
								addresses.cbegin(),
								addresses.cend(),
								[](const QHostAddress &address) {
									return MTP::IsPublicAddress(address);
								})),
					shared->_publicFailure
						? u"public failure records resolver failure"_q
						: u"public selection observes a public resolved address"_q);
				Note(u"public resolver completed: host=%1 error=%2 addresses=%3"_q.arg(
					host,
					HostInfoErrorName(info.error()),
					QString::number(addresses.size())));
				shared->maybeFinishPublic();
			});
		if (_lookupId < 0) {
			Fail(u"start public resolver"_q);
			_resolutionWritten = false;
			maybeFinishPublic();
		}
	}

	void maybeFinishPublic() {
		if (_publicReplyFinished && _resolutionWritten) {
			QTimer::singleShot(0, [shared = shared_from_this()] {
				if (shared->_publicReplyFinished && shared->_resolutionWritten) {
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

	void startCanceledSelection() {
		startLocalDiscovery(
			QString::fromLatin1(kDiscoveryDestination),
			true,
			true,
			false,
			false,
			[shared = shared_from_this()](MTP::ServerDiscoveryResult) {
				Fail(u"canceled discovery completed"_q);
				shared->settle();
			});
		QTimer::singleShot(50, [shared = shared_from_this()] {
			if (shared->_done || !shared->_discovery) {
				return;
			}
			shared->_discovery->cancel();
			shared->_discoveryAttempt.reset();
			QTimer::singleShot(150, [shared] {
				Check(
					shared->_discoveryCallbacks == 0,
					u"canceled discovery has no completion callback"_q);
				shared->settle();
			});
		});
	}

	void startFailedSelection() {
		startLocalDiscovery(
			QString::fromLatin1(kFailureDestination),
			false,
			false,
			false,
			true,
			[](MTP::ServerDiscoveryResult) {});
	}

	void startPartialSelection() {
		startLocalDiscovery(
			QString::fromLatin1(kDiscoveryDestination),
			true,
			false,
			true,
			true,
			[](MTP::ServerDiscoveryResult) {});
	}

	void startTimedOutSelection() {
		startLocalDiscovery(
			QString::fromLatin1(kDiscoveryDestination),
			true,
			true,
			false,
			true,
			[](MTP::ServerDiscoveryResult) {});
		QTimer::singleShot(100, [shared = shared_from_this()] {
			if (shared->_done || !shared->_discovery) {
				return;
			}
			Check(
				!shared->_discovery->timeout(),
				u"live discovery timeout stops the request"_q);
		});
	}

	void startLateCallback() {
		startLocalDiscovery(
			QString::fromLatin1(kDiscoveryDestination),
			true,
			true,
			false,
			false,
			[](MTP::ServerDiscoveryResult) {});
		QTimer::singleShot(50, [shared = shared_from_this()] {
			if (shared->_done || !shared->_discovery) {
				return;
			}
			shared->_discovery->cancel();
			if (shared->_localPeer) {
				shared->_localPeer->write(LocalResponse(shared->_discoveryNonce));
				shared->_localPeer->disconnectFromHost();
			}
			QTimer::singleShot(150, [shared] {
				Check(
					shared->_discoveryCallbacks == 0,
					u"late discovery callback is discarded after cancellation"_q);
				shared->settle();
			});
		});
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
				shared->settle();
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
				shared->settle();
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
			[shared = shared_from_this(), other](MTP::ServerDiscoveryResult result) {
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
				domain.activate(not_null{ other });
				domain.activate(not_null{ shared->_account });
				shared->_account->mtp().resume();
				shared->settle();
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
				if (shared->_localServer) {
					shared->_localServer->close();
				}
				const auto committed = shared->commitResult(
					*shared->_account,
					result,
					[shared] { shared->_account->mtp().resume(); });
				Check(committed, u"failed endpoint is committed before connect"_q);
				QTimer::singleShot(500, [shared] {
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
					nullptr);
				Check(committed, u"background case pins its account first"_q);
				shared->_account->appConfig().start();
				shared->_account->appConfig().refresh(true);
				shared->_updateChecker = std::make_unique<Core::UpdateChecker>();
				shared->_updateChecker->test();
				Note(u"background refresh invoked app-config and update-check paths"_q);
				QTimer::singleShot(100, [shared] {
					Check(
						shared->_updateChecker != nullptr,
						u"background update checker was created"_q);
					shared->settle();
				});
			});
	}

	void startProxy() {
		_proxyServer = std::make_unique<QTcpServer>();
		QObject::connect(
			_proxyServer.get(),
			&QTcpServer::newConnection,
			[shared = shared_from_this()] { shared->acceptProxy(); });
		if (!_proxyServer->listen(
			QHostAddress(QString::fromLatin1(kProxyHost)),
			kProxyPort)) {
			Fail(u"start bounded SOCKS5 observer"_q);
			settle();
			return;
		}
		_socket = std::make_unique<QTcpSocket>();
		_socket->setProxy(QNetworkProxy::NoProxy);
		QObject::connect(
			_socket.get(),
			&QTcpSocket::connected,
			[shared = shared_from_this()] {
				shared->_socket->write(QByteArray::fromHex("050100"));
			});
		QObject::connect(
			_socket.get(),
			&QTcpSocket::readyRead,
			[shared = shared_from_this()] { shared->proxyClientReadyRead(); });
		connectErrors(_socket.get());
		_socket->connectToHost(
			QHostAddress(QString::fromLatin1(kProxyHost)),
			kProxyPort);
		QTimer::singleShot(1000, [shared = shared_from_this()] {
			if (!shared->_done) {
				Fail(u"bounded SOCKS5 exchange"_q);
				shared->settle();
			}
		});
	}

	void connectErrors(QTcpSocket *socket) {
		QObject::connect(
			socket,
			&QTcpSocket::errorOccurred,
			[shared = shared_from_this()](QAbstractSocket::SocketError) {
				shared->socketFinished();
			});
	}

	void socketFinished() {
		if (_done || _socketReported) {
			return;
		}
		_socketReported = true;
		const auto finished = std::move(_socketFinished);
		_socketFinished = nullptr;
		closeSocket();
		if (finished) {
			finished();
		} else {
			settle();
		}
	}

	void acceptProxy() {
		if (!_proxyServer || !_proxyServer->hasPendingConnections()) {
			return;
		}
		_proxyPeer = _proxyServer->nextPendingConnection();
		QObject::connect(
			_proxyPeer.data(),
			&QTcpSocket::readyRead,
			[shared = shared_from_this()] { shared->proxyRequestReadyRead(); });
		QObject::connect(
			_proxyPeer.data(),
			&QTcpSocket::disconnected,
			[shared = shared_from_this()] {
				if (!shared->_proxyWritten && !shared->_done) {
					Fail(u"SOCKS5 proxy received a target"_q);
					shared->settle();
				}
			});
	}

	void proxyRequestReadyRead() {
		if (!_proxyPeer || _done) {
			return;
		}
		_proxyRequest += _proxyPeer->readAll();
		if (_proxyStage == 0 && _proxyRequest.size() >= 3) {
			if (_proxyRequest.left(3) != QByteArray::fromHex("050100")) {
				Fail(u"SOCKS5 greeting is valid"_q);
				settle();
				return;
			}
			_proxyRequest.remove(0, 3);
			_proxyPeer->write(QByteArray::fromHex("0500"));
			_proxyStage = 1;
		}
		if (_proxyStage == 1 && _proxyRequest.size() >= 10) {
			const auto target = SocksConnectTarget(_proxyRequest.left(10));
			if (!target) {
				Fail(u"SOCKS5 CONNECT request is valid"_q);
				settle();
				return;
			}
			_proxyWritten = WriteProxyTargetEvidence(*target);
			Check(
				*target == QString::fromLatin1(kPinnedDestination),
				u"SOCKS5 target is the pinned endpoint"_q);
			if (!_proxyWritten) {
				settle();
				return;
			}
			_proxyPeer->write(QByteArray::fromHex("050000017f0000014a8a"));
			_proxyStage = 2;
		}
	}

	void proxyClientReadyRead() {
		if (!_socket || _done) {
			return;
		}
		_proxyResponse += _socket->readAll();
		if (_proxyClientStage == 0 && _proxyResponse.size() >= 2) {
			if (_proxyResponse.left(2) != QByteArray::fromHex("0500")) {
				Fail(u"SOCKS5 proxy selected no-authentication"_q);
				settle();
				return;
			}
			_proxyResponse.remove(0, 2);
			_socket->write(QByteArray::fromHex("050100017f0000014a8a"));
			_proxyClientStage = 1;
		}
		if (_proxyClientStage == 1 && _proxyResponse.size() >= 10) {
			Check(
				_proxyResponse.left(2) == QByteArray::fromHex("0500"),
				u"SOCKS5 proxy accepted CONNECT"_q);
			socketFinished();
		}
	}

	[[nodiscard]] bool done() const {
		return _done;
	}

	[[nodiscard]] bool evidenceWritten() const {
		return _resolutionWritten || _proxyWritten;
	}

	std::shared_ptr<NetworkCaseState> shared_from_this() {
		return _self.lock();
	}

	void setSelf(const std::shared_ptr<NetworkCaseState> &self) {
		_self = self;
	}

	std::unique_ptr<QTcpSocket> _socket;
	std::unique_ptr<QTcpServer> _proxyServer;
	std::unique_ptr<QTcpServer> _localServer;
	std::unique_ptr<Intro::details::ServerWidgetDiscovery> _discovery;
	std::unique_ptr<QNetworkAccessManager> _network;
	std::unique_ptr<Core::UpdateChecker> _updateChecker;
	QPointer<QTcpSocket> _proxyPeer;
	QPointer<QTcpSocket> _localPeer;
	QPointer<QNetworkReply> _reply;
	std::weak_ptr<NetworkCaseState> _self;
	std::optional<Intro::details::ServerWidgetDiscovery::Attempt>
		_discoveryAttempt;
	Main::Account *_account = nullptr;
	MTP::ServerSelectionCheck _selection;
	Fn<void()> _socketFinished;
	QByteArray _discoveryNonce;
	QByteArray _localRequest;
	QByteArray _proxyRequest;
	QByteArray _proxyResponse;
	int _lookupId = -1;
	int _discoveryCallbacks = 0;
	int _proxyStage = 0;
	int _proxyClientStage = 0;
	bool _done = false;
	bool _publicFailure = false;
	bool _socketReported = false;
	bool _publicReplyFinished = false;
	bool _expectDiscoveryFailure = false;
	bool _holdResponse = false;
	bool _partialResponse = false;
	bool _resolutionWritten = false;
	bool _proxyWritten = false;
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
			} else if (name == u"proxy-intermediary"_q) {
				Check(
					state->evidenceWritten(),
					u"observed SOCKS5 target evidence was written"_q);
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
