/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_serialized_request.h"
#include "mtproto/mtproto_custom_server_input.h"
#include "mtproto/mtproto_response.h"

#include <atomic>

namespace MTP {
namespace details {

class Dcenter;
class Session;

[[nodiscard]] int GetNextRequestId();

} // namespace details

// Keep the http-time special-config boundary pure and observable. The
// delegated domain is only usable when the account is allowed to use the
// production fallback path; callers still own the actual request lifetime.
[[nodiscard]] bool CanStartSpecialConfigRequest(
	const QString &delegatedDomain,
	bool networkAllowed,
	bool httpTimeValid,
	bool requestActive,
	bool refusesProductionFallback);

class DcOptions;
class Config;
struct ConfigFields;
class AuthKey;
using AuthKeyPtr = std::shared_ptr<AuthKey>;
using AuthKeysList = std::vector<AuthKeyPtr>;
enum class Environment : uchar;

// A pinned endpoint failure together with the session that reported
// it. The report is retired only by a successful connection of that
// same session: any other session of the DC reaching ConnectedState
// proves nothing about the endpoint that failed - after a stop, a
// fresh session can still connect on an existing auth key while the
// reporting one waits for a corrected pin.
struct PinnedServerFailureReport {
	ShiftedDcId shiftedDcId = 0;
	PinnedServerFailure failure = PinnedServerFailure::KeyMismatch;

	friend inline bool operator==(
			const PinnedServerFailureReport &a,
			const PinnedServerFailureReport &b) {
		return (a.shiftedDcId == b.shiftedDcId)
			&& (a.failure == b.failure);
	}
};

// Channel state for the pinned-server failure: holds the last report
// for late subscribers and answers the two policy questions with
// rules instead of judgement calls at call sites.
//
// report() emits every time, including an exact repeat of the held
// one: an assignment that compares would swallow it, but a repeated
// failure is a second occurrence and has to reach the UI again -
// steps clear their error labels on navigation, so a swallowed
// repeat reads as already handled.
//
// retireIfReportedBy() retires only for the reporting session's own
// successful connection: another session of the same DC connecting
// proves nothing about the endpoint that failed.
class PinnedServerFailureChannel {
public:
	void report(PinnedServerFailureReport report) {
		_held = report;
		_changes.fire_copy(report);
	}

	void retireIfReportedBy(ShiftedDcId dcWithShift) {
		if (!_held || (_held->shiftedDcId != dcWithShift)) {
			return;
		}
		_held.reset();
		_changes.fire_copy(std::nullopt);
	}

	[[nodiscard]] const std::optional<PinnedServerFailureReport> &current()
	const {
		return _held;
	}

	// Fires the held value on subscribe, then every report and
	// retirement; retirement carries an empty value.
	[[nodiscard]] auto updates() const
	-> rpl::producer<std::optional<PinnedServerFailureReport>> {
		return rpl::merge(
			rpl::single(_held),
			_changes.events());
	}

private:
	std::optional<PinnedServerFailureReport> _held;
	rpl::event_stream<std::optional<PinnedServerFailureReport>> _changes;

};

// State for the enrollment pause. A stop request crosses from the main
// thread to a session thread, so a request from an earlier pin must be
// identifiable and ignored after the pin is replaced.
class ServerEnrollmentGate final {
public:
	struct ResumeResult {
		bool resumed = false;
		bool wasStarted = false;
	};

	explicit ServerEnrollmentGate(bool startPaused = false)
	: _startPaused(startPaused) {
	}

	[[nodiscard]] bool start() {
		if (_started || _startPaused) {
			return false;
		}
		_started = true;
		return true;
	}

	[[nodiscard]] ResumeResult resume() {
		const auto wasPaused = _startPaused || _paused.load();
		if (!wasPaused) {
			return {};
		}
		const auto wasStarted = _started.load();
		_stopGeneration.fetch_add(1, std::memory_order_release);
		_startPaused = false;
		_paused = false;
		return { .resumed = true, .wasStarted = wasStarted };
	}

	[[nodiscard]] bool pause() {
		if (!_started) {
			return false;
		}
		if (!_paused.exchange(true)) {
			// Invalidate callbacks as soon as work is stopped. Waiting until
			// resume() leaves the whole paused interval looking current to a
			// late resolver or timer callback.
			_stopGeneration.fetch_add(1, std::memory_order_release);
		}
		return true;
	}

	[[nodiscard]] bool networkAllowed() const {
		return _started.load() && !_paused.load();
	}

	[[nodiscard]] uint64 stopToken() const {
		return _stopGeneration.load(std::memory_order_acquire);
	}

	[[nodiscard]] bool stopTokenIsCurrent(uint64 token) const {
		return token == stopToken();
	}

private:
	bool _startPaused = false;
	std::atomic_bool _started = false;
	std::atomic_bool _paused = false;
	std::atomic<uint64> _stopGeneration = 0;

};

class Instance : public QObject {
	Q_OBJECT

public:
	struct Fields {
		Fields();
		Fields(Fields &&other);
		Fields &operator=(Fields &&other);
		~Fields();

		static constexpr auto kNoneMainDc = -1;
		static constexpr auto kNotSetMainDc = 0;
		static constexpr auto kDefaultMainDc = 2;
		static constexpr auto kTemporaryMainDc = 1000;

		std::unique_ptr<Config> config;
		DcId mainDcId = kNotSetMainDc;
		AuthKeysList keys;
		QString deviceModel;
		QString systemVersion;
		// New, unauthenticated accounts are held without a session until
		// the intro flow has committed a server enrollment pin.
		bool startPaused = false;
	};

	enum class Mode {
		Normal,
		KeysDestroyer,
	};

	Instance(Mode mode, Fields &&fields);
	Instance(const Instance &other) = delete;
	Instance &operator=(const Instance &other) = delete;
	~Instance();

	void resolveProxyDomain(const QString &host);
	void setGoodProxyDomain(
		const QString &host,
		const QString &ip,
		uint64 generation);
	void suggestMainDcId(DcId mainDcId);
	void setMainDcId(DcId mainDcId);
	[[nodiscard]] DcId mainDcId() const;
	[[nodiscard]] rpl::producer<DcId> mainDcIdValue() const;
	[[nodiscard]] QString systemLangCode() const;
	[[nodiscard]] QString cloudLangCode() const;
	[[nodiscard]] QString langPackName() const;

	[[nodiscard]] rpl::producer<> writeKeysRequests() const;
	[[nodiscard]] rpl::producer<> allKeysDestroyed() const;

	// A pinned endpoint that failed on its face: a key the account was
	// not given, or a server DC id that does not confirm the pin.
	// Reported once and held until the session that reported it
	// connects successfully; fires the current value to late
	// subscribers, so UI attached after the failure still sees it.
	void onPinnedServerFailure(
		ShiftedDcId shiftedDcId,
		PinnedServerFailure failure);
	[[nodiscard]] auto pinnedServerFailure() const
		-> rpl::producer<std::optional<PinnedServerFailureReport>>;

	// Thread-safe.
	[[nodiscard]] Config &config() const;
	[[nodiscard]] const ConfigFields &configValues() const;
	[[nodiscard]] DcOptions &dcOptions() const;
	[[nodiscard]] Environment environment() const;
	[[nodiscard]] bool isTestMode() const;
	[[nodiscard]] QString deviceModel() const;
	[[nodiscard]] QString systemVersion() const;

	// Main thread.
	void dcPersistentKeyChanged(DcId dcId, const AuthKeyPtr &persistentKey);
	void dcTemporaryKeyChanged(DcId dcId);
	[[nodiscard]] rpl::producer<DcId> dcTemporaryKeyChanged() const;
	[[nodiscard]] AuthKeysList getKeysForWrite() const;
	void addKeysForDestroy(AuthKeysList &&keys);

	void restart();
	// Start a paused instance after its endpoint and RSA key have been
	// persisted. Calling this on an already running instance is a no-op.
	void resume();
	// Thread-safe.
	[[nodiscard]] bool isServerEnrollmentNetworkAllowed() const;
	[[nodiscard]] uint64 serverEnrollmentStopToken() const;
	[[nodiscard]] bool isServerEnrollmentStopTokenCurrent(
		uint64 token) const;

	// Main thread.
	// Stop this account's sessions while an unauthed enrollment is corrected.
	// A subsequent setCustomServer() followed by resume() lets the sessions
	// try the newly confirmed endpoint again.
	void stopForServerEnrollment();
	void restart(ShiftedDcId shiftedDcId);
	int32 dcstate(ShiftedDcId shiftedDcId = 0);
	QString dctransport(ShiftedDcId shiftedDcId = 0);
	void ping();
	void cancel(mtpRequestId requestId);
	int32 state(mtpRequestId requestId); // < 0 means waiting for such count of ms

	// Main thread.
	void killSession(ShiftedDcId shiftedDcId);
	void stopSession(ShiftedDcId shiftedDcId);
	void reInitConnection(DcId dcId);
	void logout(Fn<void()> done);

	void setUpdatesHandler(Fn<void(const Response&)> handler);
	void setGlobalFailHandler(
		Fn<void(const Error&, const Response&)> handler);
	void setStateChangedHandler(
		Fn<void(ShiftedDcId shiftedDcId, int32 state)> handler);
	void setSessionResetHandler(Fn<void(ShiftedDcId shiftedDcId)> handler);
	void clearGlobalHandlers();

	void onStateChange(ShiftedDcId shiftedDcId, int32 state);
	void onSessionReset(ShiftedDcId shiftedDcId);

	[[nodiscard]] bool hasCallback(mtpRequestId requestId) const;
	void processCallback(const Response &response);
	void processUpdate(const Response &message);

	// return true if need to clean request data
	bool rpcErrorOccured(
		const Response &response,
		const FailHandler &onFail,
		const Error &err);

	// Thread-safe.
	bool isKeysDestroyer() const;
	void keyWasPossiblyDestroyed(ShiftedDcId shiftedDcId);

	// Main thread.
	void keyDestroyedOnServer(ShiftedDcId shiftedDcId, uint64 keyId);

	void requestConfig();
	void requestConfigIfOld();
	void requestCDNConfig();
	void setUserPhone(const QString &phone);
	void badConfigurationError();

	void restartedByTimeout(ShiftedDcId shiftedDcId);
	[[nodiscard]] rpl::producer<ShiftedDcId> restartsByTimeout() const;

	[[nodiscard]] auto nonPremiumDelayedRequests() const
		-> rpl::producer<mtpRequestId>;
	[[nodiscard]] rpl::producer<> frozenErrorReceived() const;

	void syncHttpUnixtime();

	void sendAnything(ShiftedDcId shiftedDcId = 0, crl::time msCanWait = 0);

	template <typename Request>
	mtpRequestId send(
			const Request &request,
			ResponseHandler &&callbacks = {},
			ShiftedDcId shiftedDcId = 0,
			crl::time msCanWait = 0,
			mtpRequestId afterRequestId = 0,
			mtpRequestId overrideRequestId = 0) {
		const auto requestId = overrideRequestId
			? overrideRequestId
			: details::GetNextRequestId();
		sendSerialized(
			requestId,
			details::SerializedRequest::Serialize(request),
			std::move(callbacks),
			shiftedDcId,
			msCanWait,
			afterRequestId);
		return requestId;
	}

	template <typename Request>
	mtpRequestId send(
			const Request &request,
			DoneHandler &&onDone,
			FailHandler &&onFail = nullptr,
			ShiftedDcId shiftedDcId = 0,
			crl::time msCanWait = 0,
			mtpRequestId afterRequestId = 0,
			mtpRequestId overrideRequestId = 0) {
		return send(
			request,
			ResponseHandler{ std::move(onDone), std::move(onFail) },
			shiftedDcId,
			msCanWait,
			afterRequestId,
			overrideRequestId);
	}

	template <typename Request>
	mtpRequestId sendProtocolMessage(
			ShiftedDcId shiftedDcId,
			const Request &request) {
		const auto requestId = details::GetNextRequestId();
		sendRequest(
			requestId,
			details::SerializedRequest::Serialize(request),
			{},
			shiftedDcId,
			0,
			false,
			0);
		return requestId;
	}

	void sendSerialized(
			mtpRequestId requestId,
			details::SerializedRequest &&request,
			ResponseHandler &&callbacks,
			ShiftedDcId shiftedDcId,
			crl::time msCanWait,
			mtpRequestId afterRequestId) {
		const auto needsLayer = true;
		sendRequest(
			requestId,
			std::move(request),
			std::move(callbacks),
			shiftedDcId,
			msCanWait,
			needsLayer,
			afterRequestId);
	}

	[[nodiscard]] rpl::lifetime &lifetime();

Q_SIGNALS:
	void proxyDomainResolved(
		QString host,
		QStringList ips,
		qint64 expireAt);

private:
	void sendRequest(
		mtpRequestId requestId,
		details::SerializedRequest &&request,
		ResponseHandler &&callbacks,
		ShiftedDcId shiftedDcId,
		crl::time msCanWait,
		bool needsLayer,
		mtpRequestId afterRequestId);

	class Private;
	const std::unique_ptr<Private> _private;

};

} // namespace MTP
