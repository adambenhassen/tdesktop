/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "mtproto/mtproto_custom_server_input.h"

namespace {

using namespace MTP;

// Public keys only. The private-side rows are exercised by a frame with
// a junk body: the classifier stops at the frame and never touches the
// base64, so no real private key material enters this repository.

const char kRsa2048Spki[] = "\
-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxo6D8Nnc7doxTTylho4C\n\
zeigjblTm8d/Ckb8j8Th2Fj9WpBmO9kcIlG4PWmu2lysm5x1UBbkWvZVYx8AHvOx\n\
AOsqLX64MOHCt7Tv9vngecLdGV8LXbdcUKnurT2BTbHefnA851R6zVDZ4RGa0pzw\n\
n11RFAW3AL2KurBZ273CzSDA/r+UXObYu4PFcoHiO6sxo/3SWz627Xt+HzGBdbwx\n\
Hrw7CEKiSxuaWNHfENFNUdFY7LKe1eICR5zm0IzCZUg+5aOceQ/EcJgEofi27Cg+\n\
S5OWD4uyANegnJWxYG3nWcREIcC5jTfGdf7xhSvMDo2LkEv2skHcYxuV8JaHOFZ8\n\
rwIDAQAB\n\
-----END PUBLIC KEY-----";

const char kRsa1024Spki[] = "\
-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD6xsZI1S92scUwYtpGKcOaHwmu\n\
yYqCZ7qm3JDF2KTzy6j5xOLhd2us6/vJFLGl9Nw+InZ5m45/7UG+zM2fTyScFnFG\n\
G4DGeJWK9pjyICXUa9vsK4YMu7baKGHcWxMrvja1zOhltJ/XRjP8ltQelUTNrx2L\n\
z3hmx5b9PUnkQkRGowIDAQAB\n\
-----END PUBLIC KEY-----";

const char kEcSpki[] = "\
-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKfh02XT+pQdgBY/EK65ghl1uQAk5\n\
xHVw4IZv/ePauoi43UT3ozK8OrI+ImFuANXQtV45kXoLy8yf62BU6JQadg==\n\
-----END PUBLIC KEY-----";

const char kEd25519Spki[] = "\
-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAg+rx3bJvDwktiQtp1Oafl8vIO0SsrJ/W5kjlt0/7+pA=\n\
-----END PUBLIC KEY-----";

const char kRsa2048Pkcs1Pub[] = "\
-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEAxo6D8Nnc7doxTTylho4CzeigjblTm8d/Ckb8j8Th2Fj9WpBmO9kc\n\
IlG4PWmu2lysm5x1UBbkWvZVYx8AHvOxAOsqLX64MOHCt7Tv9vngecLdGV8LXbdc\n\
UKnurT2BTbHefnA851R6zVDZ4RGa0pzwn11RFAW3AL2KurBZ273CzSDA/r+UXObY\n\
u4PFcoHiO6sxo/3SWz627Xt+HzGBdbwxHrw7CEKiSxuaWNHfENFNUdFY7LKe1eIC\n\
R5zm0IzCZUg+5aOceQ/EcJgEofi27Cg+S5OWD4uyANegnJWxYG3nWcREIcC5jTfG\n\
df7xhSvMDo2LkEv2skHcYxuV8JaHOFZ8rwIDAQAB\n\
-----END RSA PUBLIC KEY-----";

// A private key frame with a junk body. The classifier stops at the
// frame and never touches the base64, so the body can be anything.
const char kPrivateFramePkcs8[] = "\
-----BEGIN PRIVATE KEY-----\n\
junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk\n\
-----END PRIVATE KEY-----";

const char kPrivateFramePkcs1[] = "\
-----BEGIN RSA PRIVATE KEY-----\n\
junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk\n\
-----END RSA PRIVATE KEY-----";

const char kPrivateFrameEncrypted[] = "\
-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk\n\
-----END ENCRYPTED PRIVATE KEY-----";

const char kPrivateFrameEc[] = "\
-----BEGIN EC PRIVATE KEY-----\n\
junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk\n\
-----END EC PRIVATE KEY-----";

const char kPrivateFrameEd25519[] = "\
-----BEGIN PRIVATE KEY-----\n\
junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk\n\
-----END PRIVATE KEY-----";

const char kPrivateFrameOpenssh[] = "\
-----BEGIN OPENSSH PRIVATE KEY-----\n\
junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk\n\
-----END OPENSSH PRIVATE KEY-----";

const char kCorruptPrivate[] = "\
-----BEGIN PRIVATE KEY-----\n\
AAAAnot base64++++\n\
-----END PRIVATE KEY-----";

// A private key frame concatenated with its own public key. The
// frame is checked before the public key is read, so the paste
// refuses as PrivateKey regardless of whether a public key also
// parses.
const char kConcatPrivThenPub[] = "\
-----BEGIN PRIVATE KEY-----\n\
junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk\n\
-----END PRIVATE KEY-----\n\
-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxo6D8Nnc7doxTTylho4C\n\
zeigjblTm8d/Ckb8j8Th2Fj9WpBmO9kcIlG4PWmu2lysm5x1UBbkWvZVYx8AHvOx\n\
AOsqLX64MOHCt7Tv9vngecLdGV8LXbdcUKnurT2BTbHefnA851R6zVDZ4RGa0pzw\n\
n11RFAW3AL2KurBZ273CzSDA/r+UXObYu4PFcoHiO6sxo/3SWz627Xt+HzGBdbwx\n\
Hrw7CEKiSxuaWNHfENFNUdFY7LKe1eICR5zm0IzCZUg+5aOceQ/EcJgEofi27Cg+\n\
S5OWD4uyANegnJWxYG3nWcREIcC5jTfGdf7xhSvMDo2LkEv2skHcYxuV8JaHOFZ8\n\
rwIDAQAB\n\
-----END PUBLIC KEY-----";

// A private key frame over the 8192 byte cap. The frame check runs
// before the size cap, so an oversized paste that carries the frame
// still refuses as PrivateKey rather than Unreadable.
[[nodiscard]] QString OversizedPrivateFrame() {
	const auto kBegin = "-----BEGIN PRIVATE KEY-----\n";
	const auto kEnd = "-----END PRIVATE KEY-----\n";
	const auto kJunk = "junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk\n";
	auto result = QString::fromLatin1(kBegin);
	while (result.size() < 8192) {
		result += QString::fromLatin1(kJunk);
	}
	result += QString::fromLatin1(kEnd);
	return result;
}

[[nodiscard]] int Status(const char *pem) {
	return int(CheckServerKey(QString::fromLatin1(pem)).status);
}

[[nodiscard]] int S(ServerKeyStatus status) {
	return int(status);
}

} // namespace

TEST_CASE(Rsa2048SpkiIsValid) {
	CHECK_EQ(Status(kRsa2048Spki), S(ServerKeyStatus::Valid));
}

TEST_CASE(Rsa2048Pkcs1PubIsValid) {
	CHECK_EQ(Status(kRsa2048Pkcs1Pub), S(ServerKeyStatus::Valid));
}

TEST_CASE(Rsa1024SpkiIsBadModulusSize) {
	CHECK_EQ(Status(kRsa1024Spki), S(ServerKeyStatus::BadModulusSize));
}

TEST_CASE(EcSpkiIsNotRsaKey) {
	CHECK_EQ(Status(kEcSpki), S(ServerKeyStatus::NotRsaKey));
}

TEST_CASE(Ed25519SpkiIsNotRsaKey) {
	CHECK_EQ(Status(kEd25519Spki), S(ServerKeyStatus::NotRsaKey));
}

TEST_CASE(Pkcs8PrivateFrameIsPrivateKey) {
	CHECK_EQ(Status(kPrivateFramePkcs8), S(ServerKeyStatus::PrivateKey));
}

TEST_CASE(Pkcs1PrivateFrameIsPrivateKey) {
	CHECK_EQ(Status(kPrivateFramePkcs1), S(ServerKeyStatus::PrivateKey));
}

TEST_CASE(EncryptedPrivateFrameIsPrivateKey) {
	CHECK_EQ(Status(kPrivateFrameEncrypted), S(ServerKeyStatus::PrivateKey));
}

TEST_CASE(EcPrivateFrameIsPrivateKey) {
	CHECK_EQ(Status(kPrivateFrameEc), S(ServerKeyStatus::PrivateKey));
}

TEST_CASE(Ed25519PrivateFrameIsPrivateKey) {
	CHECK_EQ(Status(kPrivateFrameEd25519), S(ServerKeyStatus::PrivateKey));
}

TEST_CASE(OpensshPrivateFrameIsPrivateKey) {
	CHECK_EQ(Status(kPrivateFrameOpenssh), S(ServerKeyStatus::PrivateKey));
}

TEST_CASE(CorruptPrivateFrameIsPrivateKey) {
	CHECK_EQ(Status(kCorruptPrivate), S(ServerKeyStatus::PrivateKey));
}

TEST_CASE(ConcatPrivThenPubIsPrivateKey) {
	CHECK_EQ(Status(kConcatPrivThenPub), S(ServerKeyStatus::PrivateKey));
}

TEST_CASE(OversizedPrivateFrameIsPrivateKey) {
	const auto check = CheckServerKey(OversizedPrivateFrame());
	CHECK_EQ(int(check.status), S(ServerKeyStatus::PrivateKey));
}

// A valid RSA 2048 SPKI padded past the 8192 byte cap. The padding is
// non-whitespace so it survives the trimmed() call. The cap refuses the
// input before it reaches the PEM reader; the PEM reader would also
// reject it (it is strict about trailing content), so this case guards
// the cap as the first line of defense against oversized paste.
[[nodiscard]] QString PaddedValidKey() {
	const auto key = QString::fromLatin1(kRsa2048Spki);
	const auto padSize = 8192 - key.size() + 64;
	return key + QString(padSize, QChar('x'));
}

TEST_CASE(PaddedValidKeyIsUnreadable) {
	const auto check = CheckServerKey(PaddedValidKey());
	CHECK_EQ(int(check.status), S(ServerKeyStatus::Unreadable));
}

TEST_CASE(GarbageIsUnreadable) {
	CHECK_EQ(Status("this is not a key at all"), S(ServerKeyStatus::Unreadable));
}

TEST_CASE(EmptyIsEmpty) {
	CHECK_EQ(Status(""), S(ServerKeyStatus::Empty));
}

TEST_CASE(WhitespaceOnlyIsEmpty) {
	CHECK_EQ(Status("   \n\t  "), S(ServerKeyStatus::Empty));
}
