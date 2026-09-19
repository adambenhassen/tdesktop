/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#ifdef _DEBUG

#include "test/test_runner.h"

#include "mtproto/mtproto_server_discovery.h"
#include "test/test_log.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonParseError>
#include <QtCore/QPointer>
#include <QtCore/QSaveFile>
#include <QtCore/QTimer>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QTcpSocket>

#include <memory>
#include <iterator>
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
constexpr auto kPinnedHost = "192.0.2.10";
constexpr auto kPinnedDestination = "192.0.2.10:443";
constexpr auto kPinnedPort = quint16(443);
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

[[nodiscard]] bool WriteBinding(
		const QString &account,
		const QString &endpoint) {
	auto object = QJsonObject();
	object.insert(u"account"_q, account);
	object.insert(u"endpoint"_q, endpoint);
	object.insert(u"key"_q, u"test-pinned-key"_q);
	auto file = QSaveFile(EvidenceFile(
		u"network-binding-%1.json"_q.arg(account)));
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
		Fail(
			u"persist endpoint binding"_q,
			u"could not open binding file for %1"_q.arg(account));
		return false;
	}
	const auto data = QJsonDocument(object).toJson(QJsonDocument::Compact);
	if (file.write(data) != data.size() || file.write("\n") != 1
		|| !file.commit()) {
		Fail(
			u"persist endpoint binding"_q,
			u"could not commit binding file for %1"_q.arg(account));
		return false;
	}
	return true;
}

[[nodiscard]] bool ReadBinding(
		const QString &account,
		const QString &expectedEndpoint) {
	auto file = QFile(EvidenceFile(
		u"network-binding-%1.json"_q.arg(account)));
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
		return false;
	}
	QJsonParseError error;
	const auto document = QJsonDocument::fromJson(file.readAll(), &error);
	if (error.error != QJsonParseError::NoError || !document.isObject()) {
		return false;
	}
	const auto object = document.object();
	return object.value(u"account"_q).toString() == account
		&& object.value(u"endpoint"_q).toString() == expectedEndpoint
		&& !object.value(u"key"_q).toString().isEmpty();
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
		const auto context = QCoreApplication::instance();
		if (!context) {
			Fail(u"public resolver context"_q);
			settle();
			return;
		}
		_lookupId = QHostInfo::lookupHost(
			host,
			context,
			[shared = shared_from_this(), host, origin](const QHostInfo &info) {
				if (shared->_done) {
					return;
				}
				shared->_lookupId = -1;
				shared->_resolutionWritten = WriteResolutionEvidence(
					host,
					origin,
					info,
					443);
				Note(u"public resolver completed: host=%1 error=%2 addresses=%3"_q.arg(
					host,
					HostInfoErrorName(info.error()),
					QString::number(info.addresses().size())));
				if (shared->_publicFailure) {
					shared->settle();
					return;
				}
				QHostAddress selected;
				for (const auto &address : info.addresses()) {
					if (MTP::IsPublicAddress(address)) {
						selected = address;
						break;
					}
				}
				Check(
					info.error() == QHostInfo::NoError
						&& !selected.isNull(),
					u"public selection resolves to a public address"_q);
				if (!selected.isNull()) {
					shared->startSocket(selected, 443);
				} else {
					shared->settle();
				}
			});
		if (_lookupId < 0) {
			Fail(u"start public resolver"_q);
			settle();
		}
	}

	void startLocalPreflight() {
		const auto selection = MTP::CheckServerSelection(
			QString::fromLatin1(kPinnedDestination));
		Check(
			selection
				&& selection.policy == MTP::ServerDiscoveryPolicy::LocalDirect,
			u"local preflight uses direct policy"_q);
		startLocalSocket(selection);
	}

	void startPinnedEndpoint() {
		const auto selection = MTP::CheckServerSelection(
			QString::fromLatin1(kPinnedDestination));
		Check(
			selection
				&& selection.policy == MTP::ServerDiscoveryPolicy::LocalDirect,
			u"pinned endpoint remains local/direct"_q);
		if (!WriteBinding(u"account-main"_q, selection.normalizedSelection)
			|| !ReadBinding(u"account-main"_q, selection.normalizedSelection)) {
			Fail(u"committed binding is readable"_q);
			settle();
			return;
		}
		startSocket(QHostAddress(QString::fromLatin1(kPinnedHost)), kPinnedPort);
	}

	void startRestartPinned() {
		const auto selection = MTP::CheckServerSelection(
			QString::fromLatin1(kPinnedDestination));
		const auto endpoint = selection.normalizedSelection;
		Check(
			WriteBinding(u"account-restart"_q, endpoint),
			u"restart persists the selected binding"_q);
		Check(
			ReadBinding(u"account-restart"_q, endpoint),
			u"restart reloads only the persisted binding"_q);
		if (!ReadBinding(u"account-restart"_q, endpoint)) {
			settle();
			return;
		}
		startSocket(QHostAddress(QString::fromLatin1(kPinnedHost)), kPinnedPort);
	}

	void startMultipleAccountIsolation() {
		const auto selected = MTP::CheckServerSelection(
			QString::fromLatin1(kPinnedDestination));
		const auto other = MTP::CheckServerSelection(u"198.51.100.10:443"_q);
		Check(
			WriteBinding(u"account-a"_q, selected.normalizedSelection),
			u"account A commits its own binding"_q);
		Check(
			!ReadBinding(u"account-b"_q, other.normalizedSelection),
			u"account B cannot reuse account A's binding"_q);
		if (!selected || !other
			|| !ReadBinding(u"account-a"_q, selected.normalizedSelection)) {
			settle();
			return;
		}
		startSocket(QHostAddress(QString::fromLatin1(kPinnedHost)), kPinnedPort);
	}

	void startSelectedEndpointFailure() {
		const auto selection = MTP::CheckServerSelection(
			QString::fromLatin1(kPinnedDestination));
		Check(
			selection && selection.policy == MTP::ServerDiscoveryPolicy::LocalDirect,
			u"failed selected endpoint remains local/direct"_q);
		startSocket(QHostAddress(QString::fromLatin1(kPinnedHost)), kPinnedPort);
	}

	void startBackgroundRefresh() {
		_refreshIndex = 0;
		startNextRefresh();
	}

	void startNextRefresh() {
		static constexpr const char *kRefreshes[] = {
			"locale/langpack",
			"app-config",
			"cdn/config",
			"update-check",
		};
		if (_refreshIndex == int(std::size(kRefreshes))) {
			settle();
			return;
		}
		const auto refresh = QString::fromLatin1(kRefreshes[_refreshIndex]);
		Note(u"bounded background refresh: %1"_q.arg(refresh));
		startSocket(
			QHostAddress(QString::fromLatin1(kPinnedHost)),
			kPinnedPort,
			[shared = shared_from_this()] {
				++shared->_refreshIndex;
				QTimer::singleShot(0, [shared] { shared->startNextRefresh(); });
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

	void startLocalSocket(
			const MTP::ServerSelectionCheck &selection) {
		_socket = std::make_unique<QTcpSocket>();
		_socket->setProxy(QNetworkProxy::NoProxy);
		QObject::connect(
			_socket.get(),
			&QTcpSocket::connected,
			[shared = shared_from_this()] {
				const auto request = MTP::BuildLocalDiscoveryRequest(
					QByteArray(32, '\0'));
				auto offset = 0;
				auto closed = false;
				Check(
					MTP::SendLocalDiscoveryRequest(
						*shared->_socket,
						request,
						offset,
						closed),
					u"local preflight request is framed"_q);
				shared->socketFinished();
			});
		connectErrors(_socket.get());
		Check(
			MTP::StartLocalDiscoverySocket(
				*_socket,
				selection,
				QHostAddress(QString::fromLatin1(kPinnedHost))),
			u"local preflight starts only for the selected endpoint"_q);
		if (!_done) {
			QTimer::singleShot(250, [shared = shared_from_this()] {
				if (!shared->_done) {
					shared->socketFinished();
				}
			});
		}
	}

	void startSocket(
			const QHostAddress &address,
			quint16 port,
			Fn<void()> finished = nullptr) {
		_socket = std::make_unique<QTcpSocket>();
		_socket->setProxy(QNetworkProxy::NoProxy);
		_socketReported = false;
		const auto generation = ++_socketGeneration;
		_socketFinished = std::move(finished);
		QObject::connect(
			_socket.get(),
			&QTcpSocket::connected,
			[shared = shared_from_this()] { shared->socketFinished(); });
		connectErrors(_socket.get());
		_socket->connectToHost(address, port);
		QTimer::singleShot(250, [shared = shared_from_this(), generation] {
			if (!shared->_done && shared->_socketGeneration == generation) {
				shared->socketFinished();
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
			_proxyPeer->write(QByteArray::fromHex("050000017f0000014a7b"));
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
			_socket->write(QByteArray::fromHex("05010001c000020a01bb"));
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
	QPointer<QTcpSocket> _proxyPeer;
	std::weak_ptr<NetworkCaseState> _self;
	Fn<void()> _socketFinished;
	QByteArray _proxyRequest;
	QByteArray _proxyResponse;
	int _lookupId = -1;
	int _refreshIndex = 0;
	int _socketGeneration = 0;
	int _proxyStage = 0;
	int _proxyClientStage = 0;
	bool _done = false;
	bool _publicFailure = false;
	bool _socketReported = false;
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
		AddNoNetworkCase(runner, name, [] {
			auto attempt = MTP::ServerDiscoveryAttempt::Acquire();
			Check(
				attempt.has_value(),
				u"canceled selection acquires a bounded attempt"_q);
			attempt.reset();
			Note(u"selection canceled before DNS or socket submission"_q);
		});
	} else if (name == u"failed-selection"_q) {
		AddNoNetworkCase(runner, name, [] {
			const auto selection = MTP::CheckServerSelection(
				QString::fromLatin1(kPublicHost));
			Check(
				!MTP::ParsePublicDiscoveryResponse(selection, QByteArray()),
				u"failed public discovery has no endpoint"_q);
		});
	} else if (name == u"partial-selection"_q) {
		AddNoNetworkCase(runner, name, [] {
			const auto response = MTP::BuildLocalDiscoveryRequest(
				QByteArray(32, '\0'));
			Check(
				!MTP::IsCompleteLocalDiscoveryResponse(response),
				u"partial discovery response is terminal"_q);
		});
	} else if (name == u"timed-out-selection"_q) {
		auto complete = std::make_shared<bool>(false);
		runner->add({
			.name = name,
			.run = [complete] {
				QTimer::singleShot(100, [complete] {
					Note(u"selection timeout canceled before network submission"_q);
					*complete = true;
				});
			},
			.until = [complete] { return *complete; },
			.timeout = crl::time(1000),
		});
	} else if (name == u"late-callback"_q) {
		struct LateState final {
			bool canceled = false;
			bool done = false;
			int generation = 0;
		};
		auto state = std::make_shared<LateState>();
		runner->add({
			.name = name,
			.run = [state] {
				const auto generation = ++state->generation;
				state->canceled = true;
				++state->generation;
				QTimer::singleShot(100, [state, generation] {
					Check(
						state->canceled && generation != state->generation,
						u"late callback observes the canceled generation"_q);
					Note(u"late callback remained inert after cancellation"_q);
					state->done = true;
				});
			},
			.until = [state] { return state->done; },
			.timeout = crl::time(1000),
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
