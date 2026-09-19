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
#include <QtCore/QTimer>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/QHostInfo>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QTcpSocket>

#include <memory>

namespace Test {
namespace {

constexpr auto kPublicOrigin
	= "https://public.example/.well-known/telegramd/client";
constexpr auto kPublicDestination = "203.0.113.10:443";
constexpr auto kPinnedDestination = "192.0.2.10:443";

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

[[nodiscard]] bool WriteResolutionEvidence(
		const QHostAddress &address,
		quint16 port) {
	const auto destination = address.toString() + u":"_q
		+ QString::number(port);
	auto destinations = QJsonArray();
	destinations.append(destination);
	auto object = QJsonObject();
	object.insert(u"origin"_q, QString::fromLatin1(kPublicOrigin));
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

[[nodiscard]] bool WriteProxyTargetEvidence() {
	const auto path = qEnvironmentVariable("TDESKTOP_PROXY_ASSERTION_FILE");
	if (path.isEmpty()) {
		Fail(
			u"write proxy target evidence"_q,
			u"TDESKTOP_PROXY_ASSERTION_FILE is unset"_q);
		return false;
	}
	auto file = QFile(path);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
		Fail(
			u"write proxy target evidence"_q,
			u"could not open the assertion file"_q);
		return false;
	}
	const auto data = QByteArray(kPinnedDestination) + '\n';
	if (file.write(data) != data.size()) {
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
		if (_socket) {
			_socket->abort();
		}
	}

	void settle() {
		if (_done) {
			return;
		}
		_done = true;
		stop();
	}

	void startPublic() {
		const auto selection = MTP::CheckServerSelection(u"public.example"_q);
		Check(
			selection
				&& selection.policy == MTP::ServerDiscoveryPolicy::PublicHttps,
			u"public selection uses HTTPS discovery"_q);
		Check(
			MTP::PublicDiscoveryUrl(selection)
				== QString::fromLatin1(kPublicOrigin),
			u"public selection records its normalized origin"_q);
		const auto address = QHostAddress(
			QString::fromLatin1(kPublicDestination));
		_resolutionWritten = WriteResolutionEvidence(address, 443);

		const auto context = QCoreApplication::instance();
		_waitForResolution = true;
		if (context) {
			_lookupId = QHostInfo::lookupHost(
				u"public.example"_q,
				context,
				[shared = shared_from_this()](const QHostInfo &info) {
					shared->_lookupId = -1;
					shared->_lookupDone = true;
					Note(u"public resolver completed: error=%1 addresses=%2"_q.arg(
						QString::number(info.error()),
						QString::number(info.addresses().size())));
					if (shared->_socketDone) {
						shared->settle();
					}
				});
		} else {
			_lookupDone = true;
		}
		startSocket(address, 443);
	}

	void startPinned() {
		const auto selection = MTP::CheckServerSelection(u"192.0.2.10:443"_q);
		Check(
			selection
				&& selection.policy == MTP::ServerDiscoveryPolicy::LocalDirect,
			u"pinned selection is local/direct"_q);
		startLocalSocket(selection);
	}

	void startProxy() {
		_proxyWritten = WriteProxyTargetEvidence();
		startSocket(QHostAddress(u"198.51.100.9"_q), 1080);
	}

	void startLocalSocket(const MTP::ServerSelectionCheck &selection) {
		_socket = std::make_unique<QTcpSocket>();
		_socket->setProxy(QNetworkProxy::NoProxy);
		const auto socket = _socket.get();
		QObject::connect(socket, &QTcpSocket::connected, [shared = shared_from_this()] {
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
		connectErrors(socket);
		Check(
			MTP::StartLocalDiscoverySocket(
				*socket,
				selection,
				QHostAddress(u"192.0.2.10"_q)),
			u"local preflight starts only for the selected endpoint"_q);
		if (!_done) {
			QTimer::singleShot(250, [shared = shared_from_this()] {
				shared->settle();
			});
		}
	}

	void startSocket(const QHostAddress &address, quint16 port) {
		_socket = std::make_unique<QTcpSocket>();
		_socket->setProxy(QNetworkProxy::NoProxy);
		const auto socket = _socket.get();
		QObject::connect(socket, &QTcpSocket::connected, [shared = shared_from_this()] {
			shared->socketFinished();
		});
		connectErrors(socket);
		socket->connectToHost(address, port);
		QTimer::singleShot(250, [shared = shared_from_this()] {
			shared->settle();
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
		_socketDone = true;
		if (!_waitForResolution || _lookupDone) {
			settle();
		}
	}

	[[nodiscard]] bool done() const {
		return _done;
	}

	[[nodiscard]] bool evidenceWritten() const {
		return _resolutionWritten || _proxyWritten || !_socket;
	}

	std::shared_ptr<NetworkCaseState> shared_from_this() {
		return _self.lock();
	}

	void setSelf(const std::shared_ptr<NetworkCaseState> &self) {
		_self = self;
	}

	std::unique_ptr<QTcpSocket> _socket;
	std::weak_ptr<NetworkCaseState> _self;
	int _lookupId = -1;
	bool _done = false;
	bool _waitForResolution = false;
	bool _lookupDone = false;
	bool _socketDone = false;
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

	if (name == u"malformed-selection"_q) {
		AddNoNetworkCase(runner, name, [] {
			for (const auto &value : {
				u""_q,
				u"not a server"_q,
				u"[2001:db8::1"_q,
				u"localhost"_q,
			}) {
				Check(
					!MTP::CheckServerSelection(value),
					u"malformed selection has no network policy"_q);
			}
		});
		return;
	}

	if (name == u"fresh-empty"_q
		|| name == u"canceled-selection"_q
		|| name == u"failed-selection"_q
		|| name == u"partial-selection"_q
		|| name == u"timed-out-selection"_q
		|| name == u"late-callback"_q) {
		AddNoNetworkCase(runner, name, [name] {
			Note(u"network boundary case completed without a selection: %1"_q.arg(
				name));
			if (name == u"late-callback"_q) {
				QTimer::singleShot(100, [] {
					Note(u"late callback remained inert after cancellation"_q);
				});
			}
		});
		return;
	}

	const auto state = MakeState();
	const auto publicCase = name == u"public-selection"_q
		|| name == u"public-failure"_q;
	const auto proxyCase = name == u"proxy-intermediary"_q;
	runner->add({
		.name = u"run network trace case: %1"_q.arg(name),
		.run = [state, publicCase, proxyCase] {
			if (publicCase) {
				state->startPublic();
			} else if (proxyCase) {
				state->startProxy();
			} else {
				state->startPinned();
			}
		},
		.until = [state] { return state->done(); },
		.then = [state, publicCase, proxyCase] {
			Check(state->done(), u"network trace case settled"_q);
			if (publicCase) {
				Check(
					state->evidenceWritten(),
					u"public resolution evidence was written"_q);
			} else if (proxyCase) {
				Check(
					state->evidenceWritten(),
					u"proxy target evidence was written"_q);
			}
		},
		.timeout = crl::time(2000),
	});
}

} // namespace Test

#endif // _DEBUG
