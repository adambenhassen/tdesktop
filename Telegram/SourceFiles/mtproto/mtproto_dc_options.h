/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/bytes.h"

#include <QtCore/QReadWriteLock>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>

namespace MTP {
namespace details {
class RSAPublicKey;
} // namespace details

// A server endpoint and its RSA key, entered by the user, that this
// account must use. While pinned, the built-in DC table and keys are
// not used and a failed config load must not fall back to production.
struct CustomServer {
	int dcId = 0;
	std::string ip;
	int port = 0;
	bool ipv6 = false;
	std::shared_ptr<details::RSAPublicKey> key;

	[[nodiscard]] bool empty() const {
		return !key;
	}
};

enum class DcType {
	Regular,
	Temporary,
	MediaCluster,
	Cdn,
};

enum class Environment : uchar {
	Production,
	Test,
};

class DcOptions {
public:
	using Flag = MTPDdcOption::Flag;
	using Flags = MTPDdcOption::Flags;
	struct Endpoint {
		Endpoint(
			DcId id,
			Flags flags,
			const std::string &ip,
			int port,
			const bytes::vector &secret)
			: id(id)
			, flags(flags)
			, ip(ip)
			, port(port)
			, secret(secret) {
		}

		DcId id;
		Flags flags;
		std::string ip;
		int port;
		bytes::vector secret;

	};

	explicit DcOptions(Environment environment);
	DcOptions(const DcOptions &other);
	~DcOptions();

	[[nodiscard]] static bool ValidateSecret(bytes::const_span secret);

	[[nodiscard]] Environment environment() const;
	[[nodiscard]] bool isTestMode() const;

	// construct methods don't notify "changed" subscribers.
	bool constructFromSerialized(const QByteArray &serialized);
	void constructFromBuiltIn();
	void constructAddOne(
		int id,
		Flags flags,
		const std::string &ip,
		int port,
		const bytes::vector &secret);
	QByteArray serialize() const;

	[[nodiscard]] rpl::producer<DcId> changed() const;
	[[nodiscard]] rpl::producer<> cdnConfigChanged() const;
	void setFromList(const MTPVector<MTPDcOption> &options);
	void addFromList(const MTPVector<MTPDcOption> &options);
	void addFromOther(DcOptions &&options);

	[[nodiscard]] std::vector<DcId> configEnumDcIds() const;

	struct Variants {
		enum Address {
			IPv4 = 0,
			IPv6 = 1,
			AddressTypeCount = 2,
		};
		enum Protocol {
			Tcp = 0,
			Http = 1,
			ProtocolCount = 2,
		};
		std::vector<Endpoint> data[AddressTypeCount][ProtocolCount];
	};
	[[nodiscard]] Variants lookup(
		DcId dcId,
		DcType type,
		bool throughProxy) const;
	[[nodiscard]] DcType dcType(ShiftedDcId shiftedDcId) const;

	void setCDNConfig(const MTPDcdnConfig &config);
	[[nodiscard]] bool hasCDNKeysForDc(DcId dcId) const;
	[[nodiscard]] details::RSAPublicKey getDcRSAKey(
		DcId dcId,
		const QVector<MTPlong> &fingerprints) const;

	// Pin the user-entered endpoint and RSA key: they replace the
	// built-in table and keys for this account. Returns false when the
	// server carries no key, so a caller with an endpoint but no key
	// can report the failure instead of silently pinning nothing.
	// Returns false as well when a *different* server is already pinned
	// after this account was authorized for that pin. Peer and message
	// ids are server-scoped, so once they can exist a second server is a
	// second account, never an edit of the first. Before authorization,
	// correcting the pin succeeds, including replacing its key at the
	// same address. Re-applying the identical pin succeeds in both
	// states, so startup and config rewrites go through.
	[[nodiscard]] bool setCustomServer(const CustomServer &server);
	[[nodiscard]] bool markAuthorized(DcId dcId);
	[[nodiscard]] bool isAuthorized(DcId dcId) const;
	[[nodiscard]] bool clearAuthorized();
	[[nodiscard]] CustomServer customServer() const;
	[[nodiscard]] bool hasCustomServer() const;
	// True when the pinned key is the only RSA key this account may
	// use for that DC id, so a CDN key for it must be refused.
	[[nodiscard]] bool isCustomServerPinned(DcId dcId) const;

	// Hold no endpoint and no RSA key at all, and accept none from
	// anywhere. Used for an account pinned to a custom server whose
	// stored settings could not be read back: it must be unable to
	// reach any server rather than fall back to the built-in table.
	void constructBlocked();
	[[nodiscard]] bool blocked() const;

	// True when this account must never go looking for Telegram's own
	// servers: it is pinned to a user-entered endpoint, or blocked
	// because that endpoint could not be restored. The DNS and Firebase
	// resolvers exist only to find production DCs, so they must not run.
	[[nodiscard]] bool refusesProductionFallback() const;

	// Debug feature for now.
	bool loadFromFile(const QString &path);
	bool writeToFile(const QString &path) const;

private:
	// Callers must hold one of the lockers.
	void applyCustomServerUnlocked(const CustomServer &server);
	[[nodiscard]] bool hasCustomServerUnlocked() const;
	[[nodiscard]] bool isAuthorizedUnlocked(DcId dcId) const;
	[[nodiscard]] bool isCustomServerPinnedUnlocked(DcId dcId) const;
	// While a custom server is pinned it is the only endpoint this
	// account may use, so no other DC's addresses may enter the table
	// — least of all the built-in Telegram ones, which a pinned client
	// would otherwise keep scheduling connections to.
	[[nodiscard]] bool refusesEndpointUnlocked(DcId dcId) const;

	bool applyOneGuarded(
		DcId dcId,
		Flags flags,
		const std::string &ip,
		int port,
		const bytes::vector &secret);
	static bool ApplyOneOption(
		base::flat_map<DcId, std::vector<Endpoint>> &data,
		DcId dcId,
		Flags flags,
		const std::string &ip,
		int port,
		const bytes::vector &secret);
	static std::vector<DcId> CountOptionsDifference(
		const base::flat_map<DcId, std::vector<Endpoint>> &a,
		const base::flat_map<DcId, std::vector<Endpoint>> &b);
	static void FilterIfHasWithFlag(Variants &variants, Flag flag);

	[[nodiscard]] bool hasMediaOnlyOptionsFor(DcId dcId) const;

	void processFromList(const QVector<MTPDcOption> &options, bool overwrite);
	void computeCdnDcIds();

	void readBuiltInPublicKeys();

	class WriteLocker;
	friend class WriteLocker;

	class ReadLocker;
	friend class ReadLocker;

	const Environment _environment = Environment();
	base::flat_map<DcId, std::vector<Endpoint>> _data;
	base::flat_set<DcId> _cdnDcIds;
	base::flat_map<uint64, details::RSAPublicKey> _publicKeys;
	base::flat_map<
		DcId,
		base::flat_map<uint64, details::RSAPublicKey>> _cdnPublicKeys;
	CustomServer _customServer;
	base::flat_set<DcId> _authorizedDcIds;
	mutable QReadWriteLock _useThroughLockers;

	rpl::event_stream<DcId> _changed;
	rpl::event_stream<> _cdnConfigChanged;

	// True when we have overriden options from a .tdesktop-endpoints file.
	bool _immutable = false;

	// True when a pinned custom server could not be restored, so this
	// account must hold no endpoint and no key at all.
	bool _blocked = false;

};

} // namespace MTP
