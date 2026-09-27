/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/connection_abstract.h"
#include "base/timer.h"

#include <QtCore/QList>
#include <QtNetwork/QHostAddress>

class QHostInfo;

namespace MTP::details {

class ServerResolvingConnection final : public AbstractConnection {
public:
	ServerResolvingConnection(
		not_null<Instance*> instance,
		QThread *thread,
		const ProxyData &proxy,
		DcOptions::Variants::Protocol protocol,
		bool ipv6,
		const QString &hostname);

	ConnectionPointer clone(const ProxyData &proxy) override;

	crl::time pingTime() const override;
	crl::time fullConnectTimeout() const override;
	void sendData(mtpBuffer &&buffer) override;
	void disconnectFromServer() override;
	void connectToServer(
		const QString &address,
		int port,
		const bytes::vector &protocolSecret,
		int16 protocolDcId,
		bool protocolForFiles) override;
	void timedOut() override;
	bool isConnected() const override;

	int32 debugState() const override;

	QString transport() const override;
	QString tag() const override;
	QString endpoint() const override;

private:
	void lookupFinished(const QHostInfo &info);
	void setChild(ConnectionPointer &&child);
	void tryNextAddress();
	void emitError(int errorCode);
	void handleError(int errorCode);
	void handleConnected();
	void handleDisconnected();
	void handleReceivedData();

	const not_null<Instance*> _instance;
	const DcOptions::Variants::Protocol _protocol;
	const bool _ipv6 = false;
	const QString _hostname;
	ConnectionPointer _child;
	QList<QHostAddress> _addresses;
	QString _dialledAddress;
	bytes::vector _protocolSecret;
	int _port = 0;
	int16 _protocolDcId = 0;
	bool _protocolForFiles = false;
	int _nextAddress = 0;
	qint64 _lookupId = -1;
	quint64 _lookupGeneration = 0;
	int _lastErrorCode = kErrorCodeOther;
	bool _connected = false;
	bool _errorEmitted = false;
	base::Timer _lookupTimeoutTimer;
	base::Timer _addressTimeoutTimer;

};

} // namespace MTP::details
