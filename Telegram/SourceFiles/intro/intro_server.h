/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "intro/intro_step.h"
#include "mtproto/mtproto_server_discovery.h"

#include <QtCore/QByteArray>

class QNetworkAccessManager;
class QNetworkReply;
class QHostInfo;
class QTcpSocket;
class QTimer;

namespace Ui {
class FlatLabel;
class InputField;
class LinkButton;
class RoundButton;
class ScrollArea;
class VerticalLayout;
} // namespace Ui

namespace Intro {
namespace details {

class ServerWidget final : public Step {
public:
	ServerWidget(
		QWidget *parent,
		not_null<Main::Account*> account,
		not_null<Data*> data);

	bool hasBack() const override {
		return true;
	}

	[[nodiscard]] int nextButtonTop() const override;

	void setInnerFocus() override;
	void activate() override;
	void cancelled() override;
	void submit() override;

	[[nodiscard]] rpl::producer<QString> nextButtonText() const override;
	[[nodiscard]] QWidget *firstTabWidget() const override;
	[[nodiscard]] QWidget *lastTabWidget() const override;
	[[nodiscard]] QWidget *nextButtonFocusWidget() const override;

protected:
	void resizeEvent(QResizeEvent *e) override;

private:
	void layoutContent();
	void setupSelection();
	void setupBound();
	void switchToBound();
	void selectionChanged();
	void submitSelection();
	void beginPublicDiscovery();
	void beginLocalDiscovery();
	void sendLocalRequest();
	void localReadyRead();
	void discoveryTimeout();
	void discoveryFinished(MTP::ServerDiscoveryResult result);
	void resolvePublicEndpoint(MTP::ServerDiscoveryResult result);
	void publicEndpointResolved(
		MTP::ServerDiscoveryResult result,
		const QHostInfo &info);
	void discoveryFailed(bool connectionFailure);
	void cancelDiscovery();
	void showStatus(const QString &text, bool error);
	void clearStatus();
	void announceStatus();
	void commitBinding(const MTP::ServerDiscoveryResult &result);
	[[nodiscard]] QString selectionError(
		MTP::ServerSelectionStatus status) const;
	[[nodiscard]] bool readOnly() const;

	object_ptr<Ui::ScrollArea> _scroll;
	Ui::VerticalLayout *_content = nullptr;
	Ui::FlatLabel *_addressLabel = nullptr;
	Ui::InputField *_address = nullptr;
	Ui::FlatLabel *_status = nullptr;
	Ui::RoundButton *_continue = nullptr;
	Ui::FlatLabel *_savedAddressLabel = nullptr;
	Ui::FlatLabel *_savedAddress = nullptr;
	Ui::FlatLabel *_savedStatus = nullptr;
	Ui::RoundButton *_savedContinue = nullptr;
	Ui::LinkButton *_addAccount = nullptr;

	QNetworkAccessManager *_network = nullptr;
	QNetworkReply *_reply = nullptr;
	QByteArray _publicResponse;
	int _hostLookupId = -1;
	QTcpSocket *_socket = nullptr;
	QTimer *_deadline = nullptr;
	QByteArray _localNonce;
	QByteArray _localRequest;
	QByteArray _localResponse;
	int _localWriteOffset = 0;

	MTP::ServerSelectionCheck _selection;
	bool _readOnly = false;
	bool _connecting = false;
	bool _localWriteClosed = false;
	bool _suppressChanges = false;
	uint64 _attempt = 0;
};

} // namespace details
} // namespace Intro
