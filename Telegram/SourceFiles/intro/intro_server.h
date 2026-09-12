/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "intro/intro_step.h"
#include "mtproto/mtproto_server_enrollment.h"

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

class ServerKeyWidget;

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
	void enrollmentChanged();
	void reviewEnrollment();
	void showEnrollmentStatus(const QString &text, bool error);
	void clearEnrollmentStatus();
	void announceStatus();
	void setupReadOnly();
	void setupEnrollment();
	[[nodiscard]] bool readOnly() const;

	object_ptr<Ui::ScrollArea> _scroll;
	Ui::VerticalLayout *_content = nullptr;
	Ui::FlatLabel *_enrollmentLabel = nullptr;
	Ui::InputField *_enrollment = nullptr;
	Ui::FlatLabel *_status = nullptr;
	Ui::RoundButton *_review = nullptr;
	Ui::FlatLabel *_savedAddressLabel = nullptr;
	Ui::FlatLabel *_savedAddress = nullptr;
	Ui::FlatLabel *_savedIdentityLabel = nullptr;
	Ui::FlatLabel *_savedIdentity = nullptr;
	Ui::LinkButton *_savedCopy = nullptr;
	Ui::FlatLabel *_savedStatus = nullptr;
	Ui::LinkButton *_addAccount = nullptr;

	QString _savedIdentityRaw;
	QString _savedIdentityRows;
	bool _readOnly = false;
	bool _suppressChanges = false;
	bool _privateKeyWarning = false;
	uint64 _reviewSerial = 0;
};

class ServerKeyWidget final : public Step {
public:
	ServerKeyWidget(
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
	void keyPressEvent(QKeyEvent *e) override;
	bool eventFilter(QObject *receiver, QEvent *e) override;

private:
	void layoutContent();
	void updateVerdict();
	void reserveVerdictHeight();
	void commitAndAdvance();
	void replaceEnrollment();
	void copyIdentity();
	void setVerdict(MTP::KeyIdCompare status);
	void showSaveFailure();
	void announceVerdict();

	MTP::ServerEnrollmentCheck _check;

	object_ptr<Ui::ScrollArea> _scroll;
	Ui::VerticalLayout *_content = nullptr;
	Ui::FlatLabel *_endpointLabel = nullptr;
	Ui::FlatLabel *_endpoint = nullptr;
	Ui::VerticalLayout *_panel = nullptr;
	Ui::FlatLabel *_identityLabel = nullptr;
	Ui::FlatLabel *_identity = nullptr;
	Ui::LinkButton *_copy = nullptr;
	Ui::FlatLabel *_compareLabel = nullptr;
	Ui::InputField *_compare = nullptr;
	Ui::FlatLabel *_verdict = nullptr;
	Ui::FlatLabel *_verdictMeasure = nullptr;
	Ui::FlatLabel *_secondary = nullptr;
	Ui::LinkButton *_replace = nullptr;
	Ui::RoundButton *_confirm = nullptr;

	MTP::KeyIdCompare _compareStatus = MTP::KeyIdCompare::None;
	QString _panelA11yBase;
	QString _identityRows;
	bool _confirming = false;
	bool _saveFailed = false;
};

} // namespace details
} // namespace Intro
