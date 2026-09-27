/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/connection_server_resolving.h"

#include "mtproto/mtproto_server_discovery.h"

#include <QtNetwork/QDnsLookup>
#include <QtNetwork/QHostInfo>

#include <utility>

namespace MTP::details {
namespace {

constexpr auto kAddressTimeout = crl::time(4000);
constexpr auto kLookupTimeout = crl::time(8000);
constexpr auto kMaxAddresses = 8;

#ifdef TDESKTOP_UNIT_TESTS
QHostAddress TestNameserver;
quint16 TestNameserverPort = 0;
#endif

qint64 LookupServerHostname(
		const QString &hostname,
		QObject *context,
		bool ipv6,
		Fn<void(const QHostInfo &)> callback) {
	const auto lookup = new QDnsLookup(
		ipv6 ? QDnsLookup::AAAA : QDnsLookup::A,
		hostname,
		context);
#ifdef TDESKTOP_UNIT_TESTS
	if (!TestNameserver.isNull()) {
		lookup->setNameserver(TestNameserver, TestNameserverPort);
	}
#endif
	QObject::connect(
		lookup,
		&QDnsLookup::finished,
		lookup,
		[lookup, callback = std::move(callback)] {
			auto info = QHostInfo();
			if (lookup->error() == QDnsLookup::NoError) {
				auto addresses = QList<QHostAddress>();
				for (const auto &record : lookup->hostAddressRecords()) {
					addresses.push_back(record.value());
				}
				info.setAddresses(addresses);
			} else if (lookup->error() == QDnsLookup::NotFoundError) {
				info.setError(QHostInfo::HostNotFound);
			} else {
				info.setError(QHostInfo::UnknownError);
			}
			callback(info);
			lookup->deleteLater();
		});
	const auto id = static_cast<qint64>(
		reinterpret_cast<quintptr>(lookup));
	lookup->lookup();
	return id;
}

void AbortServerHostnameLookup(qint64 lookupId) {
	const auto lookup = reinterpret_cast<QDnsLookup*>(
		static_cast<quintptr>(lookupId));
	if (!lookup) {
		return;
	}
	lookup->abort();
	lookup->deleteLater();
}

ServerHostnameResolver DefaultServerHostnameResolver() {
	return {
		.lookup = LookupServerHostname,
		.abort = AbortServerHostnameLookup,
	};
}

} // namespace

#ifdef TDESKTOP_UNIT_TESTS
void SetServerHostnameResolverTestNameserver(
		const QHostAddress &address,
		quint16 port) {
	TestNameserver = address;
	TestNameserverPort = port;
}
#endif

ConnectionPointer CreateServerConnection(
		not_null<Instance*> instance,
		DcOptions::Variants::Protocol protocol,
		QThread *thread,
		const bytes::vector &secret,
		const ProxyData &proxy,
		const QString &hostname,
		bool ipv6,
		ServerHostnameResolver resolver) {
	if (ShouldResolveServerHostname(hostname, proxy.type)) {
		if (!resolver.lookup) {
			resolver = DefaultServerHostnameResolver();
		} else if (!resolver.abort) {
			resolver.abort = AbortServerHostnameLookup;
		}
		return ConnectionPointer::New<ServerResolvingConnection>(
			instance,
			thread,
			proxy,
			protocol,
			ipv6,
			hostname,
			std::move(resolver));
	}
	return AbstractConnection::Create(
		instance,
		protocol,
		thread,
		secret,
		proxy);
}

ServerResolvingConnection::ServerResolvingConnection(
		not_null<Instance*> instance,
		QThread *thread,
		const ProxyData &proxy,
		DcOptions::Variants::Protocol protocol,
		bool ipv6,
		const QString &hostname,
		ServerHostnameResolver resolver)
: AbstractConnection(thread, proxy)
, _instance(instance)
, _protocol(protocol)
, _ipv6(ipv6)
, _hostname(hostname)
, _resolver(std::move(resolver))
, _lookupTimeoutTimer([=] { emitError(kErrorCodeOther); })
, _addressTimeoutTimer([=] { handleError(kErrorCodeOther); }) {
}

ConnectionPointer ServerResolvingConnection::clone(const ProxyData &proxy) {
	Unexpected("ServerResolvingConnection::clone call.");
}

void ServerResolvingConnection::setChild(ConnectionPointer &&child) {
	_child = std::move(child);
	connect(
		_child,
		&AbstractConnection::receivedData,
		this,
		&ServerResolvingConnection::handleReceivedData);
	connect(
		_child,
		&AbstractConnection::receivedSome,
		this,
		&AbstractConnection::receivedSome);
	connect(
		_child,
		&AbstractConnection::error,
		this,
		&ServerResolvingConnection::handleError);
	connect(
		_child,
		&AbstractConnection::connected,
		this,
		&ServerResolvingConnection::handleConnected);
	connect(
		_child,
		&AbstractConnection::disconnected,
		this,
		&ServerResolvingConnection::handleDisconnected);
}

void ServerResolvingConnection::lookupFinished(const QHostInfo &info) {
	if (_errorEmitted) {
		return;
	}
	_lookupId = -1;
	_lookupActive = false;
	_lookupTimeoutTimer.cancel();
	if (info.error() != QHostInfo::NoError) {
		emitError(kErrorCodeOther);
		return;
	}
	_addresses = FilterPinnedServerAddresses(
		_hostname,
		info.addresses(),
		_ipv6);
	if (_addresses.isEmpty()) {
		emitError(kErrorCodeOther);
		return;
	}
	tryNextAddress();
}

void ServerResolvingConnection::tryNextAddress() {
	if (_connected || _errorEmitted) {
		return;
	}
	if (_nextAddress >= _addresses.size()) {
		emitError(_lastErrorCode);
		return;
	}

	const auto address = _addresses.at(_nextAddress++);
	_dialledAddress = address.toString();
	setChild(AbstractConnection::Create(
		_instance,
		_protocol,
		thread(),
		_protocolSecret,
		_proxy));
	_addressTimeoutTimer.callOnce(kAddressTimeout);
	_child->connectToServer(
		_dialledAddress,
		_port,
		_protocolSecret,
		_protocolDcId,
		_protocolForFiles);
}

void ServerResolvingConnection::emitError(int errorCode) {
	if (_errorEmitted) {
		return;
	}
	_errorEmitted = true;
	if (_lookupActive && _lookupId >= 0) {
		_resolver.abort(_lookupId);
		_lookupId = -1;
	}
	_lookupActive = false;
	_lookupTimeoutTimer.cancel();
	_addressTimeoutTimer.cancel();
	_child = nullptr;
	error(errorCode);
}

void ServerResolvingConnection::handleError(int errorCode) {
	if (_connected) {
		emitError(errorCode);
		return;
	}
	_lastErrorCode = errorCode;
	_child = nullptr;
	_addressTimeoutTimer.cancel();
	tryNextAddress();
}

void ServerResolvingConnection::handleConnected() {
	_connected = true;
	_addressTimeoutTimer.cancel();
	connected();
}

void ServerResolvingConnection::handleDisconnected() {
	if (_connected) {
		disconnected();
	} else {
		handleError(kErrorCodeOther);
	}
}

void ServerResolvingConnection::handleReceivedData() {
	Expects(_child != nullptr);
	auto &mine = received();
	auto &theirs = _child->received();
	for (auto &item : theirs) {
		mine.push_back(std::move(item));
	}
	theirs.clear();
	receivedData();
}

crl::time ServerResolvingConnection::pingTime() const {
	Expects(_child != nullptr);
	return _child->pingTime();
}

crl::time ServerResolvingConnection::fullConnectTimeout() const {
	return kLookupTimeout + kAddressTimeout * kMaxAddresses;
}

void ServerResolvingConnection::sendData(mtpBuffer &&buffer) {
	Expects(_child != nullptr);
	_child->sendData(std::move(buffer));
}

void ServerResolvingConnection::disconnectFromServer() {
	++_lookupGeneration;
	if (_lookupActive && _lookupId >= 0) {
		_resolver.abort(_lookupId);
		_lookupId = -1;
	}
	_lookupTimeoutTimer.cancel();
	_addressTimeoutTimer.cancel();
	_addresses.clear();
	_nextAddress = 0;
	_connected = false;
	_child = nullptr;
	_lookupActive = false;
}

void ServerResolvingConnection::connectToServer(
		const QString &,
		int port,
		const bytes::vector &protocolSecret,
		int16 protocolDcId,
		bool protocolForFiles) {
	disconnectFromServer();
	_errorEmitted = false;
	_dialledAddress.clear();
	_lastErrorCode = kErrorCodeOther;
	_port = port;
	_protocolSecret = protocolSecret;
	_protocolDcId = protocolDcId;
	_protocolForFiles = protocolForFiles;
	const auto lookupGeneration = ++_lookupGeneration;
	_lookupActive = true;
	_lookupId = _resolver.lookup(
		_hostname,
		this,
		_ipv6,
		[=](const QHostInfo &info) {
			if (lookupGeneration == _lookupGeneration) {
				lookupFinished(info);
			}
		});
	if (!_lookupActive) {
		_lookupId = -1;
	} else if (_lookupId < 0) {
		emitError(kErrorCodeOther);
	} else {
		_lookupTimeoutTimer.callOnce(kLookupTimeout);
	}
}

void ServerResolvingConnection::timedOut() {
	emitError(kErrorCodeOther);
}

bool ServerResolvingConnection::isConnected() const {
	return _child && _child->isConnected();
}

int32 ServerResolvingConnection::debugState() const {
	return _child ? _child->debugState() : -1;
}

QString ServerResolvingConnection::transport() const {
	return _child ? _child->transport() : QString();
}

QString ServerResolvingConnection::tag() const {
	return _child ? _child->tag() : QString();
}

QString ServerResolvingConnection::endpoint() const {
	return _dialledAddress;
}

} // namespace MTP::details
