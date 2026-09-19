/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/mtproto_server_discovery.h"

#include <QtCore/QByteArray>
#include <QtCore/QList>
#include <QtCore/QObject>
#include <QtNetwork/QHostAddress>

#include <functional>
#include <optional>

class QTcpSocket;

namespace Intro {
namespace details {

class ServerWidgetDiscovery final : public QObject {
public:
	struct Attempt {
		std::optional<MTP::ServerDiscoveryAttempt> token;
		bool fieldEditable = false;
		bool retryable = false;
	};

	struct Callbacks {
		std::function<void(MTP::ServerDiscoveryResult)> finished;
		std::function<void(bool)> failed;
		std::function<void()> candidateStarted;
	};

	explicit ServerWidgetDiscovery(QObject *parent);
	~ServerWidgetDiscovery() override;

	[[nodiscard]] Attempt acquireAttempt() const;

	void start(
		const MTP::ServerSelectionCheck &selection,
		const QByteArray &nonce,
		const QList<QHostAddress> &addresses,
		Callbacks callbacks);
	void cancel();

	[[nodiscard]] bool timeout();
	[[nodiscard]] bool running() const {
		return _running;
	}

private:
	void startNextAddress();
	void sendRequest();
	void readyRead();
	void fail(bool connectionFailure);
	void finish(MTP::ServerDiscoveryResult result);
	void stopSocket();

	MTP::ServerSelectionCheck _selection;
	QByteArray _nonce;
	QByteArray _request;
	QByteArray _response;
	QList<QHostAddress> _addresses;
	int _nextAddress = 0;
	int _writeOffset = 0;
	bool _writeClosed = false;
	QTcpSocket *_socket = nullptr;
	Callbacks _callbacks;
	bool _running = false;
};

} // namespace details
} // namespace Intro
