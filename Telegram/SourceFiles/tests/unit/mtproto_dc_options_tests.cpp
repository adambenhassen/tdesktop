/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include <atomic>
#include <thread>
#include <vector>

#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/mtproto_dc_options.h"

namespace {

using namespace MTP;

// Telegram's production public key. Its fingerprint is fixed by the
// MTProto specification — SHA1 over the TL serialisation of (n, e),
// bytes 12..20 read as a little-endian int64 — so the constant below is
// derivable from the protocol rather than from this implementation, and
// third-party MTProto libraries publish the same value. That is what
// makes it an oracle: a change to the digest's encoding (operand order,
// TL length prefix, padding, offset, endianness) moves the fingerprint
// off this number while still compiling and still looking plausible.
const char kProductionKey[] = "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n\
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n\
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n\
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n\
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n\
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n\
-----END RSA PUBLIC KEY-----";

constexpr auto kProductionKeyFingerprint = qint64(-3414540481677951611LL);

[[nodiscard]] bytes::const_span KeyBytes() {
	return bytes::make_span(kProductionKey, sizeof(kProductionKey) - 1);
}

[[nodiscard]] std::shared_ptr<details::RSAPublicKey> MakeKey() {
	return std::make_shared<details::RSAPublicKey>(KeyBytes());
}

[[nodiscard]] CustomServer MakeCustomServer() {
	return CustomServer{
		.dcId = 2,
		.ip = "10.4.1.7",
		.port = 8443,
		.key = MakeKey(),
	};
}

} // namespace

// The user checks the key they entered against the fingerprint telegramd
// logs at startup, so client and server have to agree on this number
// exactly. Getting it wrong is invisible at compile time and shows up
// only as an auth-key exchange that never completes.
TEST_CASE(RsaPublicKeyFingerprintMatchesTheProtocol) {
	const auto key = MakeKey();
	CHECK(key->valid());
	CHECK_EQ(qint64(key->fingerprint()), kProductionKeyFingerprint);
}

// The same key rebuilt from the (n, e) byte pair that gets persisted has
// to come out with the same fingerprint, or a pinned account stops
// recognising its own server after a restart.
TEST_CASE(RsaPublicKeySurvivesTheBytePairRoundTrip) {
	const auto key = MakeKey();
	CHECK(key->valid());

	const auto restored = details::RSAPublicKey(key->getN(), key->getE());
	CHECK(restored.valid());
	CHECK_EQ(qint64(restored.fingerprint()), kProductionKeyFingerprint);
}

// The kVersion 3 block. Endpoint identity and key bytes are written;
// the fingerprint is recomputed on load. Every field matters: without
// dcId the CDN-shadowing refusal matches nothing and the pin is
// silently ineffective.
TEST_CASE(PinnedCustomServerSurvivesSerialization) {
	auto options = DcOptions(Environment::Production);
	const auto server = MakeCustomServer();
	CHECK(options.setCustomServer(server));

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));

	CHECK(restored.hasCustomServer());
	CHECK(restored.isCustomServerPinned(server.dcId));
	CHECK(restored.refusesProductionFallback());

	const auto got = restored.customServer();
	CHECK_EQ(got.dcId, server.dcId);
	CHECK_EQ(got.ip, server.ip);
	CHECK_EQ(got.port, server.port);
	CHECK(got.key != nullptr);
	if (got.key) {
		CHECK(got.key->valid());
		CHECK_EQ(qint64(got.key->fingerprint()), kProductionKeyFingerprint);
	}
}

// An unpinned config must round-trip as unpinned rather than picking up
// a half-written pin, and must keep its production fallback.
TEST_CASE(UnpinnedConfigSurvivesSerialization) {
	auto options = DcOptions(Environment::Production);

	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(options.serialize()));

	CHECK(!restored.hasCustomServer());
	CHECK(!restored.refusesProductionFallback());
}

// A pin is all-or-nothing: a server with no key leaves an account that
// looks pinned but is not, so it has to be refused outright.
TEST_CASE(CustomServerWithoutAKeyIsRefused) {
	auto options = DcOptions(Environment::Production);
	auto server = MakeCustomServer();
	server.key = nullptr;

	CHECK(!options.setCustomServer(server));
	CHECK(!options.hasCustomServer());
}

// A blocked account could not read its pinned settings back. It must be
// unable to reach any server at all rather than quietly fall back to
// Telegram's production DCs, so stored options must not reopen it.
TEST_CASE(BlockedConfigRefusesStoredOptions) {
	auto options = DcOptions(Environment::Production);
	CHECK(options.setCustomServer(MakeCustomServer()));
	const auto serialized = options.serialize();

	auto blocked = DcOptions(Environment::Production);
	blocked.constructBlocked();
	CHECK(blocked.blocked());

	CHECK(!blocked.constructFromSerialized(serialized));
	CHECK(blocked.blocked());
	CHECK(!blocked.hasCustomServer());
	CHECK(blocked.refusesProductionFallback());
}

// A pin is immutable for the life of the account. Peer and message ids
// are small server-scoped integers, so reading one server's cached ids
// against another sends a forward for "user 12345" to an unrelated
// person. A different pin must be refused and the original kept.
TEST_CASE(PinnedCustomServerRefusesADifferentPin) {
	auto options = DcOptions(Environment::Production);
	const auto original = MakeCustomServer();
	CHECK(options.setCustomServer(original));

	auto different = MakeCustomServer();
	different.ip = "10.4.1.8";
	CHECK(!options.setCustomServer(different));

	const auto got = options.customServer();
	CHECK_EQ(got.ip, original.ip);
	CHECK_EQ(got.port, original.port);
	CHECK(options.refusesProductionFallback());
}

// The key is what authenticates the server to the client, so the same
// endpoint with a different key is still a different server.
TEST_CASE(PinnedCustomServerRefusesADifferentKey) {
	auto options = DcOptions(Environment::Production);
	CHECK(options.setCustomServer(MakeCustomServer()));

	auto n = MakeKey()->getN();
	n.back() = bytes::type(
		gsl::to_integer<unsigned char>(n.back()) ^ 0x01);
	auto forged = std::make_shared<details::RSAPublicKey>(
		n,
		MakeKey()->getE());
	CHECK(forged->valid());

	auto different = MakeCustomServer();
	different.key = forged;
	CHECK(!options.setCustomServer(different));

	const auto got = options.customServer();
	CHECK(got.key != nullptr);
	if (got.key) {
		CHECK_EQ(qint64(got.key->fingerprint()), kProductionKeyFingerprint);
	}
}

// Startup and config rewrites re-apply the stored pin through the same
// setter, so the identical pin must stay allowed.
TEST_CASE(ReapplyingTheIdenticalPinSucceeds) {
	auto options = DcOptions(Environment::Production);
	CHECK(options.setCustomServer(MakeCustomServer()));

	CHECK(options.setCustomServer(MakeCustomServer()));
	CHECK(options.hasCustomServer());
	CHECK(options.refusesProductionFallback());

	const auto serialized = options.serialize();
	auto restored = DcOptions(Environment::Production);
	CHECK(restored.constructFromSerialized(serialized));
	CHECK(restored.isCustomServerPinned(MakeCustomServer().dcId));
}

// The check and the apply must be one atomic step under the write lock.
// With the comparison in a separate read-lock scope, two concurrent
// callers can each observe an unpinned account, both proceed, and the
// later write replaces the first pin. Two distinct servers hammered at
// one DcOptions must therefore never both get accepted.
TEST_CASE(ConcurrentSetCustomServerAcceptsOnlyOneDistinctPin) {
	auto options = DcOptions(Environment::Production);

	auto other = MakeCustomServer();
	other.ip = "10.4.1.9";

	std::atomic<int> acceptedOriginal = 0;
	std::atomic<int> acceptedOther = 0;
	constexpr auto kThreads = 8;

	// Every thread waits at the gate until all of them are ready, so
	// the calls really overlap instead of serialising by accident.
	std::atomic<int> ready = 0;
	std::atomic<bool> go = false;

	auto threads = std::vector<std::thread>();
	threads.reserve(kThreads);
	for (auto i = 0; i != kThreads; ++i) {
		const auto attemptOriginal = (i % 2) == 0;
		// attemptOriginal is a loop-body local: it must be captured by
		// value, the thread runs long after the iteration is over.
		threads.emplace_back([&, attemptOriginal] {
			++ready;
			while (!go.load(std::memory_order_acquire)) {
				std::this_thread::yield();
			}
			const auto ok = options.setCustomServer(
				attemptOriginal ? MakeCustomServer() : other);
			(attemptOriginal ? acceptedOriginal : acceptedOther)
				+= (ok ? 1 : 0);
		});
	}
	while (ready.load() != kThreads) {
		std::this_thread::yield();
	}
	go.store(true, std::memory_order_release);
	for (auto &thread : threads) {
		thread.join();
	}

	CHECK((acceptedOriginal == 0) || (acceptedOther == 0));
	CHECK((acceptedOriginal + acceptedOther) > 0);
	const auto got = options.customServer();
	if (acceptedOriginal > 0) {
		CHECK_EQ(got.ip, MakeCustomServer().ip);
	} else {
		CHECK_EQ(got.ip, other.ip);
	}
}

// A refused overwrite returns before any state is touched, so it must
// not lift or weaken the production-fallback block.
TEST_CASE(RefusedOverwriteLeavesFallbackBlockInForce) {
	auto options = DcOptions(Environment::Production);
	CHECK(options.setCustomServer(MakeCustomServer()));
	CHECK(options.refusesProductionFallback());

	auto different = MakeCustomServer();
	different.ip = "10.4.1.8";
	CHECK(!options.setCustomServer(different));
	CHECK(options.refusesProductionFallback());
	CHECK(options.isCustomServerPinned(different.dcId));

	// The no-key refusal keeps the same property.
	auto keyless = MakeCustomServer();
	keyless.key = nullptr;
	CHECK(!options.setCustomServer(keyless));
	CHECK(options.refusesProductionFallback());
}
