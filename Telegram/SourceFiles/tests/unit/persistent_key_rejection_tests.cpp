/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/mtproto_dc_options.h"
#include "mtproto/persistent_key_rejection.h"

namespace {

using namespace MTP;
using namespace MTP::details;

const char kTestPublicKey[] = "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n\
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n\
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n\
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n\
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n\
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n\
-----END RSA PUBLIC KEY-----";

[[nodiscard]] CustomServer CurrentPin() {
	return {
		.dcId = 2,
		.ip = "10.4.1.7",
		.port = 8443,
		.key = std::make_shared<RSAPublicKey>(bytes::make_span(
			kTestPublicKey,
			sizeof(kTestPublicKey) - 1)),
	};
}

[[nodiscard]] ConnectionErrorInfo CurrentTcpRejection() {
	return {
		.generation = 7,
		.endpoint = u"10.4.1.7"_q,
		.port = 8443,
		.protocol = DcOptions::Variants::Tcp,
		.pin = CurrentPin(),
		.presentedKeyId = 0x1234,
	};
}

[[nodiscard]] PersistentKeyErrorDecision Decide(
		const ConnectionErrorInfo &connection,
		const CustomServer &currentPin = CurrentPin(),
		uint64 currentGeneration = 7,
		uint64 encryptionKeyId = 0x1234,
		uint64 persistentKeyId = 0x1234) {
	return DecidePersistentKey404(
		connection,
		currentPin,
		currentGeneration,
		encryptionKeyId,
		persistentKeyId);
}

} // namespace

TEST_CASE(Http404KeepsPersistentKeyAndRetries) {
	auto context = CurrentTcpRejection();
	context.protocol = DcOptions::Variants::Http;
	CHECK(Decide(context) == PersistentKeyErrorDecision::KeepAndRetry);
}

TEST_CASE(StaleConnection404KeepsPersistentKeyAndRetries) {
	auto context = CurrentTcpRejection();
	context.generation = 6;
	CHECK(Decide(context) == PersistentKeyErrorDecision::KeepAndRetry);
}

TEST_CASE(WrongPresentedKey404KeepsPersistentKeyAndRetries) {
	auto context = CurrentTcpRejection();
	context.presentedKeyId = 0x5678;
	CHECK(Decide(context) == PersistentKeyErrorDecision::KeepAndRetry);
}

TEST_CASE(ChangedPin404KeepsPersistentKeyAndRetries) {
	auto changedPin = CurrentPin();
	++changedPin.port;
	CHECK(Decide(CurrentTcpRejection(), changedPin)
		== PersistentKeyErrorDecision::KeepAndRetry);
}

TEST_CASE(Proxy404KeepsPersistentKeyAndStopsRetrying) {
	auto context = CurrentTcpRejection();
	context.proxied = true;
	context.proxyEndpoint = u"proxy.example"_q;
	context.proxyPort = 1080;
	CHECK(Decide(context) == PersistentKeyErrorDecision::KeepAndStop);
	CHECK_EQ(context.proxyEndpoint, u"proxy.example"_q);
	CHECK_EQ(context.proxyPort, 1080);
}

TEST_CASE(CurrentDirectPinnedTcp404DiscardsPresentedPersistentKey) {
	CHECK(Decide(CurrentTcpRejection())
		== PersistentKeyErrorDecision::Discard);
}
