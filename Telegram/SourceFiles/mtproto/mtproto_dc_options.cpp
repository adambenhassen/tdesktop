/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/mtproto_dc_options.h"

#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/facade.h"
#include "mtproto/connection_tcp.h"
#include "storage/serialize_common.h"

#include <QtCore/QFile>
#include <QtCore/QRegularExpression>

namespace MTP {
namespace {

constexpr auto kVersion = 3;

using namespace details;

struct BuiltInDc {
	int id;
	const char *ip;
	int port;
};

const BuiltInDc kBuiltInDcs[] = {
	{ 1, "149.154.175.50" , 443 },
	{ 2, "149.154.167.51" , 443 },
	{ 2, "95.161.76.100"  , 443 },
	{ 3, "149.154.175.100", 443 },
	{ 4, "149.154.167.91" , 443 },
	{ 5, "149.154.171.5"  , 443 },
};

const BuiltInDc kBuiltInDcsIPv6[] = {
	{ 1, "2001:0b28:f23d:f001:0000:0000:0000:000a", 443 },
	{ 2, "2001:067c:04e8:f002:0000:0000:0000:000a", 443 },
	{ 3, "2001:0b28:f23d:f003:0000:0000:0000:000a", 443 },
	{ 4, "2001:067c:04e8:f004:0000:0000:0000:000a", 443 },
	{ 5, "2001:0b28:f23f:f005:0000:0000:0000:000a", 443 },
};

const BuiltInDc kBuiltInDcsTest[] = {
	{ 1, "149.154.175.10" , 443 },
	{ 2, "149.154.167.40" , 443 },
	{ 3, "149.154.175.117", 443 }
};

const BuiltInDc kBuiltInDcsIPv6Test[] = {
	{ 1, "2001:0b28:f23d:f001:0000:0000:0000:000e", 443 },
	{ 2, "2001:067c:04e8:f002:0000:0000:0000:000e", 443 },
	{ 3, "2001:0b28:f23d:f003:0000:0000:0000:000e", 443 }
};

const char *kTestPublicRSAKeys[] = { "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR\n\
yy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv\n\
plUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/\n\
j25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1\n\
aHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO\n\
j4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB\n\
-----END RSA PUBLIC KEY-----" };

const char *kPublicRSAKeys[] = { "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n\
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n\
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n\
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n\
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n\
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n\
-----END RSA PUBLIC KEY-----" };

// A pin is all-or-nothing. Every one of these leaves an account that
// looks pinned but is not: an invalid key trips the fingerprint
// assertions, and a zero dc id matches no real DC, so the CDN refusal
// silently stops applying and the pinned key can be shadowed again.
[[nodiscard]] const char *CustomServerProblem(const CustomServer &server) {
	if (!server.key) {
		return "no RSA key";
	} else if (!server.key->valid()) {
		return "an invalid RSA key";
	} else if (!server.dcId) {
		return "no dc id";
	} else if (server.ip.empty()) {
		return "no address";
	} else if (server.port <= 0) {
		return "no port";
	}
	return nullptr;
}

// Whether two pins name the same server: the same endpoint identity and
// the same key bytes. The fingerprint alone would do in practice, but a
// pin decision should not rest on a digest.
[[nodiscard]] bool SameCustomServer(
		const CustomServer &a,
		const CustomServer &b) {
	if (a.dcId != b.dcId
		|| a.ip != b.ip
		|| a.port != b.port
		|| a.ipv6 != b.ipv6) {
		return false;
	} else if (!a.key || !b.key) {
		return false;
	}
	return a.key->getN() == b.key->getN()
		&& a.key->getE() == b.key->getE();
}

} // namespace

class DcOptions::WriteLocker {
public:
	WriteLocker(not_null<DcOptions*> that)
	: _that(that)
	, _lock(&_that->_useThroughLockers) {
	}

	void unlock() {
		_lock.unlock();
	}

	~WriteLocker() {
		_that->computeCdnDcIds();
	}

private:
	not_null<DcOptions*> _that;
	QWriteLocker _lock;

};

class DcOptions::ReadLocker {
public:
	ReadLocker(not_null<const DcOptions*> that)
	: _lock(&that->_useThroughLockers) {
	}

	void unlock() {
		_lock.unlock();
	}

private:
	QReadLocker _lock;

};

DcOptions::DcOptions(Environment environment)
: _environment(environment) {
	constructFromBuiltIn();
}

DcOptions::DcOptions(const DcOptions &other)
: _environment(other._environment) {
	// Upstream copied these unlocked, which was safe only while
	// _publicKeys was immutable after construction. Pinning a custom
	// server rewrites it at runtime, and copying a config between
	// accounts is a live path, so the read is guarded now.
	ReadLocker lock(&other);
	_data = other._data;
	_cdnDcIds = other._cdnDcIds;
	_publicKeys = other._publicKeys;
	_cdnPublicKeys = other._cdnPublicKeys;
	_customServer = other._customServer;
	_immutable = other._immutable;
	_blocked = other._blocked;
}

DcOptions::~DcOptions() = default;

bool DcOptions::ValidateSecret(bytes::const_span secret) {
	// See also TcpConnection::Protocol::Create.
	return (secret.size() >= 21 && secret[0] == bytes::type(0xEE))
		|| (secret.size() == 17 && secret[0] == bytes::type(0xDD))
		|| (secret.size() == 16)
		|| secret.empty();
}

bool DcOptions::hasCustomServerUnlocked() const {
	return !_customServer.empty();
}

bool DcOptions::isCustomServerPinnedUnlocked(DcId dcId) const {
	return hasCustomServerUnlocked() && (dcId == _customServer.dcId);
}

bool DcOptions::refusesEndpointUnlocked(DcId dcId) const {
	return _blocked
		|| (hasCustomServerUnlocked() && (dcId != _customServer.dcId));
}

void DcOptions::readBuiltInPublicKeys() {
	const auto builtin = (_environment == Environment::Test)
		? gsl::make_span(kTestPublicRSAKeys)
		: gsl::make_span(kPublicRSAKeys);
	for (const auto key : builtin) {
		const auto keyBytes = bytes::make_span(key, strlen(key));
		auto parsed = RSAPublicKey(keyBytes);
		if (parsed.valid()) {
			_publicKeys.emplace(parsed.fingerprint(), std::move(parsed));
		} else {
			LOG(("MTP Error: could not read this public RSA key:"));
			LOG((key));
		}
	}
}

Environment DcOptions::environment() const {
	return _environment;
}

bool DcOptions::isTestMode() const {
	return (_environment != Environment::Production);
}

void DcOptions::constructFromBuiltIn() {
	WriteLocker lock(this);
	_data.clear();

	readBuiltInPublicKeys();

	const auto list = isTestMode()
		? gsl::make_span(kBuiltInDcsTest)
		: gsl::make_span(kBuiltInDcs).subspan(0);
	for (const auto &entry : list) {
		const auto flags = Flag::f_static | 0;
		applyOneGuarded(entry.id, flags, entry.ip, entry.port, {});
		DEBUG_LOG(("MTP Info: adding built in DC %1 connect option: %2:%3"
			).arg(entry.id
			).arg(entry.ip
			).arg(entry.port));
	}

	const auto listv6 = isTestMode()
		? gsl::make_span(kBuiltInDcsIPv6Test)
		: gsl::make_span(kBuiltInDcsIPv6).subspan(0);
	for (const auto &entry : listv6) {
		const auto flags = Flag::f_static | Flag::f_ipv6;
		applyOneGuarded(entry.id, flags, entry.ip, entry.port, {});
		DEBUG_LOG(("MTP Info: adding built in DC %1 IPv6 connect option: "
			"%2:%3"
			).arg(entry.id
			).arg(entry.ip
			).arg(entry.port));
	}
}

void DcOptions::processFromList(
		const QVector<MTPDcOption> &options,
		bool overwrite) {
	if (options.empty() || _immutable) {
		return;
	}

	auto data = [&] {
		if (overwrite) {
			return base::flat_map<DcId, std::vector<Endpoint>>();
		}
		ReadLocker lock(this);
		return _data;
	}();
	for (auto &mtpOption : options) {
		if (mtpOption.type() != mtpc_dcOption) {
			LOG(("Wrong type in DcOptions: %1").arg(mtpOption.type()));
			continue;
		}

		auto &option = mtpOption.c_dcOption();
		auto dcId = option.vid().v;
		auto flags = option.vflags().v;
		auto ip = std::string(
			option.vip_address().v.constData(),
			option.vip_address().v.size());
		auto port = option.vport().v;
		auto secret = bytes::make_vector(option.vsecret().value_or_empty());
		ApplyOneOption(data, dcId, flags, ip, port, secret);
	}

	const auto difference = [&] {
		WriteLocker lock(this);
		// This is the one endpoint write that does not go through
		// applyOneGuarded(), so it carries its own refusal — checked
		// here, at the write and under the lock, so a pin installed
		// while this response was being parsed still wins.
		//
		// A pinned account keeps the address the user typed and
		// verified for the session. Under overwrite this table is
		// built from scratch, so a server advertising the pinned dc id
		// at some other address it knows itself by — a LAN ip, a
		// tunnel, a container address — would replace the endpoint it
		// was actually reached on and strand the client.
		if (_blocked || hasCustomServerUnlocked()) {
			return std::vector<DcId>();
		}
		auto result = CountOptionsDifference(_data, data);
		if (!result.empty()) {
			_data = std::move(data);
		}
		return result;
	}();
	for (const auto dcId : difference) {
		_changed.fire_copy(dcId);
	}
}

void DcOptions::setFromList(const MTPVector<MTPDcOption> &options) {
	processFromList(options.v, true);
}

void DcOptions::addFromList(const MTPVector<MTPDcOption> &options) {
	processFromList(options.v, false);
}

void DcOptions::addFromOther(DcOptions &&options) {
	if (this == &options || _immutable) {
		return;
	}

	auto idsChanged = std::vector<DcId>();
	{
		ReadLocker lock(&options);
		if (options._data.empty()) {
			return;
		}

		idsChanged.reserve(options._data.size());
		{
			WriteLocker lock(this);
			const auto changed = [&](const std::vector<Endpoint> &list) {
				auto result = false;
				for (const auto &endpoint : list) {
					const auto dcId = endpoint.id;
					const auto flags = endpoint.flags;
					const auto &ip = endpoint.ip;
					const auto port = endpoint.port;
					const auto &secret = endpoint.secret;
					if (applyOneGuarded(dcId, flags, ip, port, secret)) {
						result = true;
					}
				}
				return result;
			};
			for (const auto &item : base::take(options._data)) {
				if (changed(item.second)) {
					idsChanged.push_back(item.first);
				}
			}
			for (auto &item : options._cdnPublicKeys) {
				// A blocked config holds no key at all, and a CDN key
				// for the pinned custom DC id would shadow the
				// user-verified key in getDcRSAKey().
				if (_blocked || isCustomServerPinnedUnlocked(item.first)) {
					continue;
				}
				for (auto &entry : item.second) {
					_cdnPublicKeys[item.first].insert(std::move(entry));
				}
			}
		}
	}
	for (const auto dcId : idsChanged) {
		_changed.fire_copy(dcId);
	}
}

void DcOptions::constructAddOne(
		int id,
		Flags flags,
		const std::string &ip,
		int port,
		const bytes::vector &secret) {
	WriteLocker lock(this);
	applyOneGuarded(BareDcId(id), flags, ip, port, secret);
}

bool DcOptions::applyOneGuarded(
		DcId dcId,
		Flags flags,
		const std::string &ip,
		int port,
		const bytes::vector &secret) {
	if (refusesEndpointUnlocked(dcId)) {
		return false;
	}
	return ApplyOneOption(_data, dcId, flags, ip, port, secret);
}

bool DcOptions::ApplyOneOption(
		base::flat_map<DcId, std::vector<Endpoint>> &data,
		DcId dcId,
		Flags flags,
		const std::string &ip,
		int port,
		const bytes::vector &secret) {
	auto i = data.find(dcId);
	if (i != data.cend()) {
		for (auto &endpoint : i->second) {
			if (endpoint.ip == ip && endpoint.port == port) {
				return false;
			}
		}
		i->second.emplace_back(dcId, flags, ip, port, secret);
	} else {
		data.emplace(dcId, std::vector<Endpoint>(
			1,
			Endpoint(dcId, flags, ip, port, secret)));
	}
	return true;
}

std::vector<DcId> DcOptions::CountOptionsDifference(
		const base::flat_map<DcId, std::vector<Endpoint>> &a,
		const base::flat_map<DcId, std::vector<Endpoint>> &b) {
	auto result = std::vector<DcId>();
	const auto find = [](
			const std::vector<Endpoint> &where,
			const Endpoint &what) {
		for (const auto &endpoint : where) {
			if (endpoint.ip == what.ip && endpoint.port == what.port) {
				return true;
			}
		}
		return false;
	};
	const auto equal = [&](
			const std::vector<Endpoint> &m,
			const std::vector<Endpoint> &n) {
		if (m.size() != n.size()) {
			return false;
		}
		for (const auto &endpoint : m) {
			if (!find(n, endpoint)) {
				return false;
			}
		}
		return true;
	};

	auto i = begin(a);
	auto j = begin(b);
	const auto max = std::numeric_limits<DcId>::max();
	while (i != end(a) || j != end(b)) {
		const auto aId = (i == end(a)) ? max : i->first;
		const auto bId = (j == end(b)) ? max : j->first;
		if (aId < bId) {
			result.push_back(aId);
			++i;
		} else if (bId < aId) {
			result.push_back(bId);
			++j;
		} else {
			if (!equal(i->second, j->second)) {
				result.push_back(aId);
			}
			++i;
			++j;
		}
	}
	return result;
}

QByteArray DcOptions::serialize() const {
	if (_immutable) {
		// Don't write the overriden options to our settings.
		return DcOptions(_environment).serialize();
	}

	ReadLocker lock(this);

	auto size = sizeof(qint32);

	// Dc options.
	auto optionsCount = 0;
	size += sizeof(qint32);
	for (const auto &item : _data) {
		if (isTemporaryDcId(item.first)) {
			continue;
		}
		for (const auto &endpoint : item.second) {
			++optionsCount;
			// id + flags + port
			size += sizeof(qint32) + sizeof(qint32) + sizeof(qint32);
			size += sizeof(qint32) + endpoint.ip.size();
			size += sizeof(qint32) + endpoint.secret.size();
		}
	}

	// CDN public keys.
	auto count = 0;
	for (auto &keysInDc : _cdnPublicKeys) {
		count += keysInDc.second.size();
	}
	struct SerializedPublicKey {
		DcId dcId;
		bytes::vector n;
		bytes::vector e;
	};
	std::vector<SerializedPublicKey> publicKeys;
	publicKeys.reserve(count);
	size += sizeof(qint32);
	for (const auto &keysInDc : _cdnPublicKeys) {
		for (const auto &entry : keysInDc.second) {
			publicKeys.push_back({
				keysInDc.first,
				entry.second.getN(),
				entry.second.getE()
			});
			size += sizeof(qint32)
				+ Serialize::bytesSize(publicKeys.back().n)
				+ Serialize::bytesSize(publicKeys.back().e);
		}
	}

	// Pinned custom server (v3). The endpoint identity (dcId, ip,
	// port) and the key bytes are persisted; the fingerprint is
	// recomputed on load. Without dcId the CDN-shadowing control
	// cannot match and the pin is silently ineffective.
	bool pinned = false;
	qint32 customDcId = 0, customPort = 0;
	auto customIp = std::string();
	bytes::vector customKeyN, customKeyE;
	if (_customServer.key) {
		pinned = true;
		customDcId = _customServer.dcId;
		customPort = _customServer.port;
		customIp = _customServer.ip;
		customKeyN = _customServer.key->getN();
		customKeyE = _customServer.key->getE();
	}
	size += sizeof(qint32); // pinned
	if (pinned) {
		// id + port + ip size
		size += sizeof(qint32) + sizeof(qint32) + sizeof(qint32);
		size += customIp.size();
		size += Serialize::bytesSize(customKeyN)
			+ Serialize::bytesSize(customKeyE);
	}

	auto result = QByteArray();
	result.reserve(size);
	{
		QDataStream stream(&result, QIODevice::WriteOnly);
		stream.setVersion(QDataStream::Qt_5_1);
		stream << qint32(-kVersion);

		// Dc options.
		stream << qint32(optionsCount);
		for (const auto &item : _data) {
			if (isTemporaryDcId(item.first)) {
				continue;
			}
			for (const auto &endpoint : item.second) {
				stream << qint32(endpoint.id)
					<< qint32(endpoint.flags)
					<< qint32(endpoint.port)
					<< qint32(endpoint.ip.size());
				stream.writeRawData(endpoint.ip.data(), endpoint.ip.size());
				stream << qint32(endpoint.secret.size());
				stream.writeRawData(
					reinterpret_cast<const char*>(endpoint.secret.data()),
					endpoint.secret.size());
			}
		}

		// CDN public keys.
		stream << qint32(publicKeys.size());
		for (auto &key : publicKeys) {
			stream << qint32(key.dcId)
				<< Serialize::bytes(key.n)
				<< Serialize::bytes(key.e);
		}

		// Pinned custom server (v3).
		stream << qint32(pinned ? 1 : 0);
		if (pinned) {
			stream << customDcId
				<< customPort
				<< qint32(customIp.size());
			stream.writeRawData(customIp.data(), customIp.size());
			stream
				<< Serialize::bytes(customKeyN)
				<< Serialize::bytes(customKeyE);
		}
	}
	return result;
}

bool DcOptions::constructFromSerialized(const QByteArray &serialized) {
	QDataStream stream(serialized);
	stream.setVersion(QDataStream::Qt_5_1);

	auto minusVersion = qint32(0);
	stream >> minusVersion;
	const auto version = (minusVersion < 0) ? (-minusVersion) : 0;

	auto count = qint32(0);
	if (version > 0) {
		stream >> count;
	} else {
		count = minusVersion;
	}
	if (stream.status() != QDataStream::Ok) {
		LOG(("MTP Error: Bad data for DcOptions::constructFromSerialized()"));
		return false;
	}

	WriteLocker lock(this);
	if (_blocked) {
		// A blocked config takes no endpoint and no key from storage;
		// only an explicit re-pin lifts it.
		LOG(("MTP Error: refusing to deserialize into a blocked config."));
		return false;
	}
	_data.clear();
	for (auto i = 0; i != count; ++i) {
		qint32 id = 0, flags = 0, port = 0, ipSize = 0;
		stream >> id >> flags >> port >> ipSize;

		// https://stackoverflow.com/questions/1076714/max-length-for-client-ip-address
		constexpr auto kMaxIpSize = 45;
		if (ipSize <= 0 || ipSize > kMaxIpSize) {
			LOG(("MTP Error: Bad data inside DcOptions::constructFromSerialized()"));
			return false;
		}

		auto ip = std::string(ipSize, ' ');
		stream.readRawData(ip.data(), ipSize);

		constexpr auto kMaxSecretSize = 32;
		auto secret = bytes::vector();
		if (version > 0) {
			auto secretSize = qint32(0);
			stream >> secretSize;
			if (secretSize < 0 || secretSize > kMaxSecretSize) {
				LOG(("MTP Error: Bad data inside DcOptions::constructFromSerialized()"));
				return false;
			} else if (secretSize > 0) {
				secret.resize(secretSize);
				stream.readRawData(
					reinterpret_cast<char*>(secret.data()),
					secretSize);
			}
		}

		if (stream.status() != QDataStream::Ok) {
			LOG(("MTP Error: Bad data inside DcOptions::constructFromSerialized()"));
			return false;
		}

		applyOneGuarded(
			DcId(id),
			Flags::from_raw(flags),
			ip,
			port,
			secret);
	}

	// Read CDN config
	if (!stream.atEnd() && version > 1) {
		auto count = qint32(0);
		stream >> count;
		if (stream.status() != QDataStream::Ok) {
			LOG(("MTP Error: Bad data for CDN config in DcOptions::constructFromSerialized()"));
			return false;
		}

		for (auto i = 0; i != count; ++i) {
			qint32 dcId = 0;
			bytes::vector n, e;
			stream >> dcId >> Serialize::bytes(n) >> Serialize::bytes(e);
			if (stream.status() != QDataStream::Ok) {
				LOG(("MTP Error: Bad data for CDN config inside DcOptions::constructFromSerialized()"));
				return false;
			}

			auto key = RSAPublicKey(n, e);
			if (key.valid()) {
				// The pinned custom server is read after this block and
				// drops every persisted CDN key, so nothing read here can
				// shadow the user-verified key in getDcRSAKey().
				_cdnPublicKeys[dcId].emplace(
					key.fingerprint(),
					std::move(key));
			} else {
				LOG(("MTP Error: Could not read valid CDN public key."));
				return false;
			}
		}
	}

	// Read pinned custom server (v3). The endpoint identity and the
	// key bytes are persisted; the fingerprint is recomputed from the
	// key bytes on load. A truncated v3 blob must fail the whole load,
	// not silently revert to the built-in keys.
	if (version > 2) {
		auto pinned = qint32(0);
		stream >> pinned;
		if (stream.status() != QDataStream::Ok) {
			LOG(("MTP Error: Bad data for custom server in DcOptions::constructFromSerialized()"));
			return false;
		}
		if (pinned) {
			auto dcId = qint32(0), port = qint32(0), ipSize = qint32(0);
			stream >> dcId >> port >> ipSize;
			if (stream.status() != QDataStream::Ok) {
				LOG(("MTP Error: Bad data for custom server in DcOptions::constructFromSerialized()"));
				return false;
			}
			// Same bounds check as the endpoint table above.
			constexpr auto kMaxCustomIpSize = 45;
			if (ipSize < 0 || ipSize > kMaxCustomIpSize) {
				LOG(("MTP Error: Bad data for custom server in DcOptions::constructFromSerialized()"));
				return false;
			}
			auto ip = std::string(ipSize, ' ');
			stream.readRawData(ip.data(), ipSize);
			if (stream.status() != QDataStream::Ok) {
				LOG(("MTP Error: Bad data for custom server in DcOptions::constructFromSerialized()"));
				return false;
			}
			bytes::vector n, e;
			stream >> Serialize::bytes(n) >> Serialize::bytes(e);
			if (stream.status() != QDataStream::Ok) {
				LOG(("MTP Error: Bad data for custom server key in DcOptions::constructFromSerialized()"));
				return false;
			}
			// Restore the full pinned state, not just the key: the
			// endpoint identity is what the CDN-shadowing control
			// matches against, and the key must replace the built-in
			// table that the DcOptions(Environment) ctor already filled.
			//
			// ipv6 is not stored in the v3 blob, so derive it from the
			// stored ip on every load. This is the only option: every
			// blob already written carries no flag to read, and the
			// original substring scan was self-healing for the same
			// reason — it re-derived the flag from the ip on each load.
			auto hostAddr = QHostAddress(QString::fromStdString(ip));
			const auto ipv6 = (hostAddr.protocol()
				== QAbstractSocket::IPv6Protocol);
			auto restored = CustomServer{
				.dcId = dcId,
				.ip = std::move(ip),
				.port = port,
				.ipv6 = ipv6,
				.key = std::make_shared<RSAPublicKey>(RSAPublicKey(n, e))
			};
			// A blob that claims a pin but carries a partial one must
			// fail the load rather than install it: the account then
			// takes the fail-closed path instead of running with a pin
			// whose controls do not apply.
			if (const auto problem = CustomServerProblem(restored)) {
				LOG(("MTP Error: Stored custom server has %1."
					).arg(QString::fromUtf8(problem)));
				return false;
			}
			applyCustomServerUnlocked(restored);
		}
	}
	return true;
}

rpl::producer<DcId> DcOptions::changed() const {
	return _changed.events();
}

rpl::producer<> DcOptions::cdnConfigChanged() const {
	return _cdnConfigChanged.events();
}

std::vector<DcId> DcOptions::configEnumDcIds() const {
	auto result = std::vector<DcId>();
	{
		ReadLocker lock(this);
		result.reserve(_data.size());
		for (auto &item : _data) {
			const auto dcId = item.first;
			Assert(!item.second.empty());
			if (!isCdnDc(item.second.front().flags)
				&& !isTemporaryDcId(dcId)) {
				result.push_back(dcId);
			}
		}
	}
	ranges::sort(result);
	return result;
}

DcType DcOptions::dcType(ShiftedDcId shiftedDcId) const {
	if (isTemporaryDcId(shiftedDcId)) {
		return DcType::Temporary;
	}
	ReadLocker lock(this);
	if (_cdnDcIds.find(BareDcId(shiftedDcId)) != _cdnDcIds.cend()) {
		return DcType::Cdn;
	}
	const auto dcId = BareDcId(shiftedDcId);
	if (isMediaClusterDcId(shiftedDcId) && hasMediaOnlyOptionsFor(dcId)) {
		return DcType::MediaCluster;
	}
	return DcType::Regular;
}

void DcOptions::setCDNConfig(const MTPDcdnConfig &config) {
	WriteLocker lock(this);
	if (_blocked) {
		return;
	}
	_cdnPublicKeys.clear();
	for (const auto &key : config.vpublic_keys().v) {
		key.match([&](const MTPDcdnPublicKey &data) {
			// A pinned custom server is the only endpoint there is, and
			// its RSA key is the only one the account may use. A CDN
			// config answer from any reached server must not be able to
			// replace the user-verified key for the pinned DC id.
			if (isCustomServerPinnedUnlocked(data.vdc_id().v)) {
				LOG(("MTP Error: refusing CDN public key for pinned "
					"custom DC %1.").arg(data.vdc_id().v));
				return;
			}
			const auto keyBytes = bytes::make_span(data.vpublic_key().v);
			auto key = RSAPublicKey(keyBytes);
			if (key.valid()) {
				_cdnPublicKeys[data.vdc_id().v].emplace(
					key.fingerprint(),
					std::move(key));
			} else {
				LOG(("MTP Error: could not read this public RSA key:"));
				LOG((qs(data.vpublic_key())));
			}
		});
	}
	lock.unlock();

	_cdnConfigChanged.fire({});
}

void DcOptions::applyCustomServerUnlocked(const CustomServer &server) {
	Expects(CustomServerProblem(server) == nullptr);

	// A blocked config is one whose pinned server could not be read
	// back, and this is the user handing that server over again. Lift
	// the block so the endpoint takes and the config is persisted
	// again; the caller is supplying the key the block existed for.
	_blocked = false;
	_customServer = server;
	// The pinned server replaces the built-in table and key for this
	// account, it is not merged into them. Leaving the built-in
	// endpoints in place would keep a pinned client scheduling
	// connections to Telegram production; refusesEndpointUnlocked()
	// is what keeps them out afterwards.
	_data.clear();
	_publicKeys.clear();
	_publicKeys.emplace(
		_customServer.key->fingerprint(),
		*_customServer.key);
	// A CDN key for the pinned DC id would shadow the pinned key in
	// getDcRSAKey(), and telegramd advertises no CDN at all, so a
	// pinned account keeps no CDN keys.
	_cdnPublicKeys.clear();
	applyOneGuarded(
		server.dcId,
		Flag::f_static | (server.ipv6 ? Flag::f_ipv6 : Flag(0)),
		server.ip,
		server.port,
		{});
}

bool DcOptions::setCustomServer(const CustomServer &server) {
	if (const auto problem = CustomServerProblem(server)) {
		LOG(("MTP Error: setCustomServer called with %1."
			).arg(QString::fromUtf8(problem)));
		return false;
	}
	if (_immutable) {
		// serialize() emits a fresh pin-less blob while _immutable is
		// set, which would drop the key from tdata on the next write.
		LOG(("MTP Error: setCustomServer called with overriden endpoints."));
		return false;
	}
	{
		ReadLocker lock(this);
		if (hasCustomServerUnlocked()
			&& !SameCustomServer(_customServer, server)) {
			// A pinned account's peer and message ids are small
			// server-scoped integers: reading them against another
			// server sends a forward for "user 12345" to an unrelated
			// person. A second server is a second account, never an
			// edit of this one. The identical pin stays allowed, since
			// startup and config rewrites go through here. Returning
			// before applyCustomServerUnlocked() also leaves _blocked,
			// the production-fallback block, exactly as it was.
			LOG(("MTP Error: refusing to replace pinned custom server"
				" %1:%2 with %3:%4."
				).arg(QString::fromStdString(_customServer.ip)
				).arg(_customServer.port
				).arg(QString::fromStdString(server.ip)
				).arg(server.port));
			return false;
		}
	}
	{
		WriteLocker lock(this);
		applyCustomServerUnlocked(server);
	}
	// Main::Account::startMtp() writes the config to tdata on this, and
	// that write is what puts the pinned key in the kVersion 3 blob.
	_changed.fire_copy(server.dcId);
	return true;
}

CustomServer DcOptions::customServer() const {
	ReadLocker lock(this);
	return _customServer;
}

bool DcOptions::hasCustomServer() const {
	ReadLocker lock(this);
	return hasCustomServerUnlocked();
}

bool DcOptions::isCustomServerPinned(DcId dcId) const {
	ReadLocker lock(this);
	return isCustomServerPinnedUnlocked(dcId);
}

void DcOptions::constructBlocked() {
	WriteLocker lock(this);
	_blocked = true;
	_data.clear();
	_publicKeys.clear();
	_cdnPublicKeys.clear();
	_customServer = CustomServer();
}

bool DcOptions::blocked() const {
	ReadLocker lock(this);
	return _blocked;
}

bool DcOptions::refusesProductionFallback() const {
	ReadLocker lock(this);
	return _blocked || hasCustomServerUnlocked();
}

bool DcOptions::hasCDNKeysForDc(DcId dcId) const {
	ReadLocker lock(this);
	return _cdnPublicKeys.find(dcId) != _cdnPublicKeys.cend();
}

RSAPublicKey DcOptions::getDcRSAKey(
		DcId dcId,
		const QVector<MTPlong> &fingerprints) const {
	const auto findKey = [&](
			const base::flat_map<uint64, RSAPublicKey> &keys) {
		for (const auto &fingerprint : fingerprints) {
			const auto it = keys.find(static_cast<uint64>(fingerprint.v));
			if (it != keys.cend()) {
				return it->second;
			}
		}
		return RSAPublicKey();
	};
	// _publicKeys stops being immutable after construction once a custom
	// server is pinned into it, so both reads stay under the lock.
	ReadLocker lock(this);
	const auto it = _cdnPublicKeys.find(dcId);
	if (it != _cdnPublicKeys.cend()) {
		// A CDN key must not be able to shadow the pinned key, so a
		// fingerprint miss here falls through instead of returning empty.
		const auto key = findKey(it->second);
		if (key.valid()) {
			return key;
		}
	}
	return findKey(_publicKeys);
}

auto DcOptions::lookup(
		DcId dcId,
		DcType type,
		bool throughProxy) const -> Variants {
	using Flag = Flag;
	auto result = Variants();

	ReadLocker lock(this);
	const auto i = _data.find(dcId);
	if (i == end(_data)) {
		return result;
	}
	for (const auto &endpoint : i->second) {
		const auto flags = endpoint.flags;
		if (type == DcType::Cdn && !(flags & Flag::f_cdn)) {
			continue;
		} else if (type != DcType::MediaCluster
			&& (flags & Flag::f_media_only)) {
			continue;
		} else if (!ValidateSecret(endpoint.secret)) {
			continue;
		}
		const auto address = (flags & Flag::f_ipv6)
			? Variants::IPv6
			: Variants::IPv4;
		result.data[address][Variants::Tcp].push_back(endpoint);
		if (!(flags & (Flag::f_tcpo_only | Flag::f_secret))) {
			result.data[address][Variants::Http].push_back(endpoint);
		}
	}
	if (type == DcType::MediaCluster) {
		FilterIfHasWithFlag(result, Flag::f_media_only);
	}
	if (throughProxy) {
		FilterIfHasWithFlag(result, Flag::f_static);
	}
	return result;
}

bool DcOptions::hasMediaOnlyOptionsFor(DcId dcId) const {
	ReadLocker lock(this);
	const auto i = _data.find(dcId);
	if (i == end(_data)) {
		return false;
	}
	for (const auto &endpoint : i->second) {
		const auto flags = endpoint.flags;
		if (flags & Flag::f_media_only) {
			return true;
		}
	}
	return false;
}

void DcOptions::FilterIfHasWithFlag(Variants &variants, Flag flag) {
	const auto is = [&](const Endpoint &endpoint) {
		return (endpoint.flags & flag) != 0;
	};
	const auto has = [&](const std::vector<Endpoint> &list) {
		return ranges::any_of(list, is);
	};
	for (auto &byAddress : variants.data) {
		for (auto &list : byAddress) {
			if (has(list)) {
				list = ranges::views::all(
					list
				) | ranges::views::filter(
					is
				) | ranges::to_vector;
			}
		}
	}
}

void DcOptions::computeCdnDcIds() {
	_cdnDcIds.clear();
	for (auto &item : _data) {
		Assert(!item.second.empty());
		if (item.second.front().flags & Flag::f_cdn) {
			_cdnDcIds.insert(BareDcId(item.first));
		}
	}
}

bool DcOptions::loadFromFile(const QString &path) {
	if (hasCustomServer() || blocked()) {
		// Loading endpoints sets _immutable, and serialize() then emits
		// a fresh pin-less blob, so the next write would drop the
		// pinned key from tdata for good while this object still
		// reports hasCustomServer().
		LOG(("MTP Error: refusing to load '%1' over a pinned custom "
			"server.").arg(path));
		return false;
	}
	QVector<MTPDcOption> options;

	QFile f(path);
	if (!f.open(QIODevice::ReadOnly)) {
		LOG(("MTP Error: could not read '%1'").arg(path));
		return false;
	}
	QTextStream stream(&f);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
	stream.setCodec("UTF-8");
#endif // Qt < 6.0.0
	while (!stream.atEnd()) {
		static const auto RegExp = QRegularExpression(R"(\s)");
		auto line = stream.readLine();
		auto components = line.split(RegExp, Qt::SkipEmptyParts);
		if (components.isEmpty() || components[0].startsWith('#')) {
			continue;
		}

		auto error = [line] {
			LOG(("MTP Error: in .tdesktop-endpoints expected 'dcId host port [tcpo_only] [media_only]', got '%1'").arg(line));
			return false;
		};
		if (components.size() < 3) {
			return error();
		}
		auto dcId = components[0].toInt();
		auto ip = components[1];
		auto port = components[2].toInt();
		auto host = QHostAddress();
		if (dcId <= 0 || dcId >= kDcShift || !host.setAddress(ip) || port <= 0) {
			return error();
		}
		auto flags = Flags(0);
		if (host.protocol() == QAbstractSocket::IPv6Protocol) {
			flags |= Flag::f_ipv6;
		}
		for (auto &option : components.mid(3)) {
			if (option.startsWith('#')) {
				break;
			} else if (option == u"tcpo_only"_q) {
				flags |= Flag::f_tcpo_only;
			} else if (option == u"media_only"_q) {
				flags |= Flag::f_media_only;
			} else {
				return error();
			}
		}
		options.push_back(MTP_dcOption(
			MTP_flags(flags),
			MTP_int(dcId),
			MTP_string(ip),
			MTP_int(port),
			MTPbytes()));
	}
	if (options.isEmpty()) {
		LOG(("MTP Error: in .tdesktop-endpoints expected at least one endpoint being provided."));
		return false;
	}

	_immutable = false;
	setFromList(MTP_vector<MTPDcOption>(options));
	_immutable = true;

	return true;
}

bool DcOptions::writeToFile(const QString &path) const {
	QFile f(path);
	if (!f.open(QIODevice::WriteOnly)) {
		return false;
	}
	QTextStream stream(&f);
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
	stream.setCodec("UTF-8");
#endif // Qt < 6.0.0

	ReadLocker lock(this);
	for (const auto &item : _data) {
		for (const auto &option : item.second) {
			stream
				<< option.id
				<< ' '
				<< QString::fromStdString(option.ip)
				<< ' ' << option.port;
			if (option.flags & Flag::f_tcpo_only) {
				stream << " tcpo_only";
			}
			if (option.flags & Flag::f_media_only) {
				stream << " media_only";
			}
			stream << '\n';
		}
	}
	return true;
}

} // namespace MTP
