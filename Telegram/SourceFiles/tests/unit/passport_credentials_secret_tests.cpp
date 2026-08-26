/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "passport/passport_encryption.h"

#include <QtCore/QByteArray>

#include <vector>

namespace {

using namespace Passport;

// The public key arrives with the authorization request, so these
// fixtures stand in for request-derived key text: a valid RSA key, a
// readable key that is not RSA, a readable RSA key too small to encrypt
// the credentials secret, and text that is not a key at all.

const char kRsa2048Spki[] = "\
-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1cJQAD8Vsoqr8UUZ1UnM\n\
ARDOmaC3FLnjRWlenDREB4VMxCJvskugstlsXgUA8x4NNvNWsgT9v07fAHsrAeB9\n\
FxfkXYXv1Am5HNJXwrqjPkmWz3Rh5Ju8kwqH8Zq87+dVtBLdjxuSKISZ0rdRj+Rt\n\
HyOkdcoKduZp+CAKv8b6+gCDiWr6QLKEiUDr9v7Jn6cT5VV9ad8vJ3BW/SRjhTzW\n\
rx31sXXQTaxO8OGmCWv/yUnXH194Rh/uGdDzQ4GkA4K256KJcX7nzNbzxaSt2O1i\n\
H8lbzYIhPc0hFKVSY7Aeq2Go60su+icoIMxaZs2fkSpTCGm3PrerftMYZpmtBV9I\n\
GQIDAQAB\n\
-----END PUBLIC KEY-----";

// A readable RSA key whose modulus is 64 bytes. OAEP with SHA-1
// leaves 22 bytes for plaintext at that key size, so the 32-byte
// secret below exceeds it: the key parses, the encryption fails, and
// the result must be a failure.
const char kRsa512Spki[] = "\
-----BEGIN PUBLIC KEY-----\n\
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMCQIEy1bSOHTVRDejkObrOyasRbJOPm\n\
mnN1fGe0VRWi/adXFZTN7Bx3qU8kkeLwiAiryRl7tqogIbuYOLYp5usCAwEAAQ==\n\
-----END PUBLIC KEY-----";

const char kEcSpki[] = "\
-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIRiCppTPQnLTVQEqi/cF8hZ+C9As\n\
kWAzLeM1F5P+xBzUAFvssTiQoHsYZsiAkKAzESLAdB9Zg/ErL4qajyWBqQ==\n\
-----END PUBLIC KEY-----";

const char kNotAKey[] = "not-a-public-key";

[[nodiscard]] bytes::vector MakeSecret() {
	const auto size = 32;
	auto result = bytes::vector(size, gsl::byte{});
	for (auto i = 0; i != size; ++i) {
		result[i] = bytes::type(i);
	}
	return result;
}

} // namespace

// The request key is not a PEM block at all. The parse is fallible,
// the submit fails, and nothing derived from the text is produced.
TEST_CASE(MalformedRequestKeyFails) {
	const auto secret = MakeSecret();
	const auto result = EncryptCredentialsSecret(
		bytes::make_span(secret),
		bytes::make_span(kNotAKey));
	CHECK(!result.has_value());
}

// A readable public key that is not RSA fails the same way: no
// assertion, no ciphertext, no empty or zero-filled stand-in.
TEST_CASE(NonRsaRequestKeyFails) {
	const auto secret = MakeSecret();
	const auto result = EncryptCredentialsSecret(
		bytes::make_span(secret),
		bytes::make_span(kEcSpki));
	CHECK(!result.has_value());
}

// A readable RSA key that cannot encrypt the secret: the encryption
// itself is fallible and the failure is reported, not an empty buffer.
TEST_CASE(EncryptionFailureFails) {
	const auto secret = MakeSecret();
	const auto result = EncryptCredentialsSecret(
		bytes::make_span(secret),
		bytes::make_span(kRsa512Spki));
	CHECK(!result.has_value());
}

// The unchanged success path: the existing OAEP ciphertext has the key
// modulus size and is non-empty. OAEP salts the padding, so the
// ciphertext is not stable across calls; a second call must still
// succeed with the same shape.
TEST_CASE(ValidRequestKeyEncrypts) {
	const auto secret = MakeSecret();
	const auto keySpan = bytes::make_span(kRsa2048Spki);
	const auto result = EncryptCredentialsSecret(
		bytes::make_span(secret),
		keySpan);
	CHECK(result.has_value());
	if (result) {
		CHECK_EQ(int(result->size()), 256);
		auto nonEmpty = false;
		for (const auto &b : *result) {
			if (b != bytes::type(0)) {
				nonEmpty = true;
				break;
			}
		}
		CHECK(nonEmpty);
		const auto again = EncryptCredentialsSecret(
			bytes::make_span(secret),
			keySpan);
		CHECK(again.has_value());
		if (again) {
			CHECK_EQ(int(again->size()), 256);
		}
	}
}
