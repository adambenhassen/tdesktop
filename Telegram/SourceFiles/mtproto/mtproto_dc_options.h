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
	// built-in table and keys for this account.
	void setCustomServer(const CustomServer &server);
	[[nodiscard]] const CustomServer &customServer() const {
		return _customServer;
	}
	[[nodiscard]] bool hasCustomServer() const {
		return !_customServer.empty();
	}
	// True when the custom server is pinned and its key is the only
	// RSA key the account may use for the pinned DC id.
	[[nodiscard]] bool isCustomServerPinned() const;
	[[nodiscard]] bool isCustomServerPinned(DcId dcId) const;

	// Debug feature for now.
	bool loadFromFile(const QString &path);
	bool writeToFile(const QString &path) const;

private:
	// True when the built-in table is replaced by the pinned custom
	// server, so the built-in keys are not loaded into _publicKeys.
	[[nodiscard]] bool customServerReplacesBuiltIn() const;

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
	mutable QReadWriteLock _useThroughLockers;

	rpl::event_stream<DcId> _changed;
	rpl::event_stream<> _cdnConfigChanged;

	// True when we have overriden options from a .tdesktop-endpoints file.
	bool _immutable = false;

};

} // namespace MTP
