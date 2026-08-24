/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "mtproto/mtproto_custom_server_input.h"

#include <QtCore/QStringList>

#include <string>
#include <vector>

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

// The same pair the other way round: the public key first, the private
// key appended after it. This is the paste a user actually makes by
// accident, by sending the whole key file rather than its public half,
// and it is the ordering that says the scan covers the whole text. With
// the private frame in the first block every other fixture here is
// still refused by a scan that reads only that block, so without this
// one the "anywhere in the paste" guarantee is unpinned — and the way
// it fails is the bad one: the public key parses, so the paste reports
// Valid and the user is never told they handled a secret.
const char kConcatPubThenPriv[] = "\
-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxo6D8Nnc7doxTTylho4C\n\
zeigjblTm8d/Ckb8j8Th2Fj9WpBmO9kcIlG4PWmu2lysm5x1UBbkWvZVYx8AHvOx\n\
AOsqLX64MOHCt7Tv9vngecLdGV8LXbdcUKnurT2BTbHefnA851R6zVDZ4RGa0pzw\n\
n11RFAW3AL2KurBZ273CzSDA/r+UXObYu4PFcoHiO6sxo/3SWz627Xt+HzGBdbwx\n\
Hrw7CEKiSxuaWNHfENFNUdFY7LKe1eICR5zm0IzCZUg+5aOceQ/EcJgEofi27Cg+\n\
S5OWD4uyANegnJWxYG3nWcREIcC5jTfGdf7xhSvMDo2LkEv2skHcYxuV8JaHOFZ8\n\
rwIDAQAB\n\
-----END PUBLIC KEY-----\n\
-----BEGIN PRIVATE KEY-----\n\
junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk\n\
-----END PRIVATE KEY-----";

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

// The frame is refused wherever it sits, not only when it opens the
// paste. A scan narrowed to the first PEM block refuses every other
// fixture here unchanged and accepts this one as a usable key.
TEST_CASE(ConcatPubThenPrivIsPrivateKey) {
	CHECK_EQ(Status(kConcatPubThenPriv), S(ServerKeyStatus::PrivateKey));
}

TEST_CASE(OversizedPrivateFrameIsPrivateKey) {
	const auto check = CheckServerKey(OversizedPrivateFrame());
	CHECK_EQ(int(check.status), S(ServerKeyStatus::PrivateKey));
}

// A valid RSA 2048 SPKI padded past the 8192 byte cap. The newline
// after the END marker keeps the PEM block well-formed; the padding
// is non-whitespace so it survives trimmed(). Without the cap the
// reader accepts the input and the case goes red on cap-line delete.
[[nodiscard]] QString PaddedValidKey() {
	const auto key = QString::fromLatin1(kRsa2048Spki);
	const auto padSize = 8192 - key.size() + 64;
	return key + '\n' + QString(padSize, QChar('x'));
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

namespace {

// The identity of kRsa2048Spki, derived from OpenSSL and not from this
// implementation. The whole point of the value is that it agrees with
// what a server computes on its own, so pinning whatever the client
// currently returns would pin a wrong encoding just as happily. To
// regenerate it, write kRsa2048Spki to key.pem and run:
//
//   openssl pkey -pubin -in key.pem -outform DER | openssl dgst -sha256
//
// then split the 64 hex characters into 16 dash-separated groups of
// four. Measured with OpenSSL 3.0.13.
const char kRsa2048Identity[] = "\
2c71-40fe-bd64-0fb0-2783-598e-1bac-d718-\
d185-e7c6-3699-7044-7574-2013-d085-9e7a";

[[nodiscard]] QString Identity(const char *pem) {
	return CheckServerKey(QString::fromLatin1(pem)).identity;
}

} // namespace

TEST_CASE(Rsa2048IdentityIsTheOpensslSpkiDigest) {
	CHECK_EQ(Identity(kRsa2048Spki), QString::fromLatin1(kRsa2048Identity));
}

// The same key written PKCS#1 instead of SPKI. The identity names the
// key, not the armor it arrived in, so re-encoding has to reproduce the
// SPKI byte for byte rather than digesting whatever the user pasted.
TEST_CASE(Pkcs1PubHasTheSameIdentity) {
	CHECK_EQ(
		Identity(kRsa2048Pkcs1Pub),
		QString::fromLatin1(kRsa2048Identity));
}

TEST_CASE(IdentityOfAnInvalidKeyIsEmpty) {
	CHECK_EQ(ServerKeyIdentity(details::RSAPublicKey()), QString());
}

TEST_CASE(IdentityMatchesIgnoringDashesSpaceAndCase) {
	const auto computed = QString::fromLatin1(kRsa2048Identity);
	CHECK(ServerKeyIdentityMatches(computed, computed));
	CHECK(ServerKeyIdentityMatches(computed.toUpper(), computed));
	auto undashed = computed;
	CHECK(ServerKeyIdentityMatches(undashed.remove('-'), computed));
	auto spaced = computed;
	CHECK(ServerKeyIdentityMatches(spaced.replace('-', ' '), computed));
}

// All-or-nothing on purpose: a prefix that compares equal is exactly the
// "close enough" answer that would let a user accept the wrong key.
TEST_CASE(IdentityDoesNotMatchAPrefixOrANearMiss) {
	const auto computed = QString::fromLatin1(kRsa2048Identity);
	CHECK(!ServerKeyIdentityMatches(computed.left(computed.size() - 1), computed));
	CHECK(!ServerKeyIdentityMatches(computed.left(4), computed));
	CHECK(!ServerKeyIdentityMatches(computed + QString::fromLatin1("0"), computed));
	CHECK(!ServerKeyIdentityMatches(QString(), computed));
	auto oneOff = computed;
	oneOff.replace(0, 1, QChar::fromLatin1('3'));
	CHECK(!ServerKeyIdentityMatches(oneOff, computed));
	CHECK(!ServerKeyIdentityMatches(
		QString::fromLatin1("not an identity"),
		computed));
}

// The comparison has to refuse when neither side is an identity, not
// just when they differ. Both sides normalize to nothing whenever the
// key was refused — ServerKeyIdentity returns empty for those — so an
// equality that ignored emptiness would report a match on a key that
// was never read, which is the one answer the confirmation step must
// never give. Every case above compares against a real identity, so
// none of them reaches the emptiness guard.
TEST_CASE(IdentityDoesNotMatchWhenNeitherSideIsAnIdentity) {
	const auto empty = QString();
	// Text that survives to the comparison as nothing: dashes and
	// whitespace are dropped, and a non-hex character empties the
	// normalized form outright.
	const auto dashes = QString::fromLatin1("----");
	const auto blank = QString::fromLatin1("  \t ");
	const auto words = QString::fromLatin1("no key was read");
	CHECK(!ServerKeyIdentityMatches(empty, empty));
	CHECK(!ServerKeyIdentityMatches(dashes, dashes));
	CHECK(!ServerKeyIdentityMatches(words, words));
	CHECK(!ServerKeyIdentityMatches(dashes, blank));
	CHECK(!ServerKeyIdentityMatches(blank, empty));
	CHECK(!ServerKeyIdentityMatches(words, empty));
	// The shape it actually takes in the UI: a key that was refused has
	// no identity, so `computed` is empty whatever the user typed.
	const auto refused = CheckServerKey(QString::fromLatin1(kEcSpki));
	CHECK(refused.identity.isEmpty());
	CHECK(!ServerKeyIdentityMatches(empty, refused.identity));
	CHECK(!ServerKeyIdentityMatches(
		QString::fromLatin1(kRsa2048Identity),
		refused.identity));
}

namespace {

struct NamedPem {
	const char *name = nullptr;
	QString pem;
};

// Every input the validator refuses, including the two generated ones:
// the guarantee is about all of them, not only the ones that happen to
// be string literals.
[[nodiscard]] std::vector<NamedPem> RefusedKeys() {
	const auto latin1 = [](const char *value) {
		return QString::fromLatin1(value);
	};
	return {
		{ "empty", QString() },
		{ "whitespace", latin1("   \n\t  ") },
		{ "garbage", latin1("this is not a key at all") },
		{ "rsa1024", latin1(kRsa1024Spki) },
		{ "ec", latin1(kEcSpki) },
		{ "ed25519", latin1(kEd25519Spki) },
		{ "pkcs8Private", latin1(kPrivateFramePkcs8) },
		{ "pkcs1Private", latin1(kPrivateFramePkcs1) },
		{ "encryptedPrivate", latin1(kPrivateFrameEncrypted) },
		{ "ecPrivate", latin1(kPrivateFrameEc) },
		{ "ed25519Private", latin1(kPrivateFrameEd25519) },
		{ "opensshPrivate", latin1(kPrivateFrameOpenssh) },
		{ "corruptPrivate", latin1(kCorruptPrivate) },
		{ "concatPrivThenPub", latin1(kConcatPrivThenPub) },
		{ "concatPubThenPriv", latin1(kConcatPubThenPriv) },
		{ "oversizedPrivate", OversizedPrivateFrame() },
		{ "paddedValid", PaddedValidKey() },
	};
}

// Names the refused inputs that left something usable behind, so a
// failure says which one rather than just "false".
[[nodiscard]] QString RefusedKeysLeavingResidue() {
	auto result = QStringList();
	for (const auto &entry : RefusedKeys()) {
		const auto check = CheckServerKey(entry.pem);
		if (check.valid()
			|| bool(check)
			|| !check.key.empty()
			|| !check.identity.isEmpty()) {
			result.append(QString::fromLatin1(entry.name));
		}
	}
	return result.join(QString::fromLatin1(", "));
}

} // namespace

// A caller that ignores the status must not be able to pick up half of a
// refused key: nothing usable survives a refusal, whatever the reason.
TEST_CASE(RefusedKeyLeavesNothingBehind) {
	CHECK_EQ(RefusedKeysLeavingResidue(), QString());
}

// The other half of the guarantee above. Without this a validator that
// returned an empty check for everything would satisfy it.
TEST_CASE(AcceptedKeyCarriesTheKeyAndTheIdentity) {
	const auto check = CheckServerKey(QString::fromLatin1(kRsa2048Spki));
	CHECK(check.valid());
	CHECK(bool(check));
	CHECK(check.key.valid());
	CHECK_EQ(check.key.modulusBits(), 2048);
	CHECK_EQ(check.identity, QString::fromLatin1(kRsa2048Identity));
}

namespace {

[[nodiscard]] int EndpointStatus(const char *value) {
	return int(CheckServerEndpoint(QString::fromLatin1(value)).status);
}

[[nodiscard]] int E(ServerEndpointStatus status) {
	return int(status);
}

// kMaxHostSize is 45, the length of the longest IPv6 literal, so a host
// of exactly that many characters is the last one accepted.
[[nodiscard]] QString HostOfSize(int size, int port) {
	const auto suffix = QString::fromLatin1(".com");
	return QString(size - suffix.size(), QChar::fromLatin1('a'))
		+ suffix
		+ QChar::fromLatin1(':')
		+ QString::number(port);
}

} // namespace

TEST_CASE(EndpointEmpty) {
	CHECK_EQ(EndpointStatus(""), E(ServerEndpointStatus::Empty));
	CHECK_EQ(EndpointStatus("   \n\t  "), E(ServerEndpointStatus::Empty));
}

TEST_CASE(EndpointNoPort) {
	CHECK_EQ(EndpointStatus("example.com"), E(ServerEndpointStatus::NoPort));
	CHECK_EQ(EndpointStatus("127.0.0.1"), E(ServerEndpointStatus::NoPort));
	CHECK_EQ(EndpointStatus("[::1]"), E(ServerEndpointStatus::NoPort));
}

TEST_CASE(EndpointBadPort) {
	CHECK_EQ(EndpointStatus("example.com:"), E(ServerEndpointStatus::BadPort));
	CHECK_EQ(EndpointStatus("example.com:http"), E(ServerEndpointStatus::BadPort));
	CHECK_EQ(EndpointStatus("example.com:44a"), E(ServerEndpointStatus::BadPort));
	// toInt() would take both of these; a port is digits.
	CHECK_EQ(EndpointStatus("example.com:+443"), E(ServerEndpointStatus::BadPort));
	CHECK_EQ(EndpointStatus("example.com: 443"), E(ServerEndpointStatus::BadPort));
	CHECK_EQ(EndpointStatus("example.com:0"), E(ServerEndpointStatus::BadPort));
	CHECK_EQ(EndpointStatus("example.com:65536"), E(ServerEndpointStatus::BadPort));
	CHECK_EQ(EndpointStatus("example.com:99999999999"), E(ServerEndpointStatus::BadPort));
	// Brackets closed, then something that is not ":port".
	CHECK_EQ(EndpointStatus("[::1]443"), E(ServerEndpointStatus::BadPort));
}

TEST_CASE(EndpointEmptyHost) {
	CHECK_EQ(EndpointStatus(":443"), E(ServerEndpointStatus::EmptyHost));
	CHECK_EQ(EndpointStatus("[]:443"), E(ServerEndpointStatus::EmptyHost));
}

TEST_CASE(EndpointBadHost) {
	CHECK_EQ(EndpointStatus("[::1:443"), E(ServerEndpointStatus::BadHost));
	// Brackets say "IP literal", so a hostname inside them is a typo.
	CHECK_EQ(EndpointStatus("[example.com]:443"), E(ServerEndpointStatus::BadHost));
	CHECK_EQ(EndpointStatus("exa_mple.com:443"), E(ServerEndpointStatus::BadHost));
	CHECK_EQ(EndpointStatus("-example.com:443"), E(ServerEndpointStatus::BadHost));
	CHECK_EQ(EndpointStatus("example-.com:443"), E(ServerEndpointStatus::BadHost));
	CHECK_EQ(EndpointStatus("example..com:443"), E(ServerEndpointStatus::BadHost));
	CHECK_EQ(EndpointStatus("exam ple.com:443"), E(ServerEndpointStatus::BadHost));
}

TEST_CASE(EndpointHostTooLong) {
	CHECK_EQ(
		int(CheckServerEndpoint(HostOfSize(46, 443)).status),
		E(ServerEndpointStatus::HostTooLong));
	CHECK_EQ(
		int(CheckServerEndpoint(HostOfSize(45, 443)).status),
		E(ServerEndpointStatus::Valid));
}

// Two colons and no brackets is an IPv6 address with or without a port,
// and there is no telling which. Splitting at the last colon would
// silently pin a prefix of the address the user meant.
TEST_CASE(EndpointUnbracketedIPv6) {
	CHECK_EQ(EndpointStatus("::1:443"), E(ServerEndpointStatus::UnbracketedIPv6));
	CHECK_EQ(
		EndpointStatus("2001:db8::1:443"),
		E(ServerEndpointStatus::UnbracketedIPv6));
	CHECK_EQ(EndpointStatus("::1"), E(ServerEndpointStatus::UnbracketedIPv6));
}

TEST_CASE(EndpointValidIPv4) {
	const auto check = CheckServerEndpoint(QString::fromLatin1("127.0.0.1:443"));
	CHECK_EQ(int(check.status), E(ServerEndpointStatus::Valid));
	CHECK(check.valid());
	CHECK(bool(check));
	CHECK_EQ(check.host, std::string("127.0.0.1"));
	CHECK_EQ(check.port, 443);
	CHECK_EQ(check.ipv6, false);
}

// The brackets are how the user writes it; the host that comes back is
// the bare address, and ipv6 has to be set or the endpoint is built for
// the wrong family.
TEST_CASE(EndpointValidIPv6) {
	const auto check = CheckServerEndpoint(
		QString::fromLatin1("[2001:db8::1]:8443"));
	CHECK_EQ(int(check.status), E(ServerEndpointStatus::Valid));
	CHECK_EQ(check.host, std::string("2001:db8::1"));
	CHECK_EQ(check.port, 8443);
	CHECK_EQ(check.ipv6, true);
}

TEST_CASE(EndpointValidHostname) {
	const auto check = CheckServerEndpoint(
		QString::fromLatin1("  telegramd.example.com:443  "));
	CHECK_EQ(int(check.status), E(ServerEndpointStatus::Valid));
	CHECK_EQ(check.host, std::string("telegramd.example.com"));
	CHECK_EQ(check.port, 443);
	CHECK_EQ(check.ipv6, false);
}

TEST_CASE(EndpointPortBoundsAreInclusive) {
	CHECK_EQ(EndpointStatus("example.com:1"), E(ServerEndpointStatus::Valid));
	CHECK_EQ(EndpointStatus("example.com:65535"), E(ServerEndpointStatus::Valid));
}

namespace {

// One refused endpoint per reason, named so a failure says which one
// rather than just "false".
[[nodiscard]] QString RefusedEndpointsLeavingResidue() {
	const auto refused = QStringList()
		<< QString()
		<< QString::fromLatin1("   ")
		<< QString::fromLatin1("example.com")
		<< QString::fromLatin1("[::1]")
		<< QString::fromLatin1("example.com:")
		<< QString::fromLatin1("example.com:0")
		<< QString::fromLatin1("example.com:65536")
		<< QString::fromLatin1("[::1]443")
		<< QString::fromLatin1(":443")
		<< QString::fromLatin1("[::1:443")
		<< QString::fromLatin1("[example.com]:443")
		<< QString::fromLatin1("exa_mple.com:443")
		<< QString::fromLatin1("::1:443")
		<< HostOfSize(46, 443);
	auto result = QStringList();
	for (const auto &value : refused) {
		const auto check = CheckServerEndpoint(value);
		if (check.valid()
			|| bool(check)
			|| !check.host.empty()
			|| check.port
			|| check.ipv6) {
			result.append(u"\"%1\""_q.arg(value));
		}
	}
	return result.join(QString::fromLatin1(", "));
}

} // namespace

TEST_CASE(RefusedEndpointLeavesNothingBehind) {
	CHECK_EQ(RefusedEndpointsLeavingResidue(), QString());
}

// The identity of a valid key must be 64 hex chars joined into 16
// dash-separated groups of 4, totalling 64 + 15 = 79 characters.
TEST_CASE(ValidKeyIdentityIs79Chars) {
	const auto check = CheckServerKey(QString::fromLatin1(kRsa2048Spki));
	CHECK(check.valid());
	CHECK_EQ(check.identity.size(), 79);
}

// Letter case must be ignored when comparing the typed value against
// the computed identity. Test with a real 64-digit identity and its
// uppercased form so both sides pass NormalizedIdentity's length check.
TEST_CASE(IdentityMatchIsCaseInsensitive) {
	const auto check = CheckServerKey(QString::fromLatin1(kRsa2048Spki));
	CHECK(check.valid());
	CHECK(ServerKeyIdentityMatches(check.identity.toUpper(), check.identity));
}

// A typed value with fewer than 64 hex digits never matches, even if
// the digits present are a correct prefix of the computed identity.
TEST_CASE(IdentityDifferentHexLengthIsNoMatch) {
	const auto check = CheckServerKey(QString::fromLatin1(kRsa2048Spki));
	CHECK(check.valid());
	// Take the first 20 characters of the 79-char identity: that is
	// about 16 hex digits, well short of the required 64.
	const auto prefix = check.identity.left(20);
	CHECK(!ServerKeyIdentityMatches(prefix, check.identity));
}

// A valid key's identity must round-trip through ServerKeyIdentityMatches
// when typed back verbatim.
TEST_CASE(ValidKeyIdentityMatchesItself) {
	const auto check = CheckServerKey(QString::fromLatin1(kRsa2048Spki));
	CHECK(check.valid());
	CHECK(ServerKeyIdentityMatches(check.identity, check.identity));
}

// ExtractKeyId: plain text returns trimmed text unchanged.
TEST_CASE(ExtractKeyIdReturnsPlainTextTrimmed) {
	CHECK_EQ(ExtractKeyId(u"  abcd1234  "_q), u"abcd1234"_q);
}

// ExtractKeyId: a logfmt line yields the value after key_id=.
TEST_CASE(ExtractKeyIdParsesLogfmtLine) {
	CHECK_EQ(
		ExtractKeyId(u"msg=\"server RSA key\" key_id=abc123 ts=1"_q),
		u"abc123"_q);
}

// ExtractKeyId: a quoted logfmt value has its surrounding quotes stripped.
TEST_CASE(ExtractKeyIdStripsQuotesFromLogfmt) {
	CHECK_EQ(
		ExtractKeyId(u"key_id=\"550a-1234\""_q),
		u"550a-1234"_q);
}

// ExtractKeyId: a full log line whose next field starts with a hex character
// ('f' in fingerprint=...) must not absorb any of that field — stop at 64.
TEST_CASE(ExtractKeyIdStopsAt64BeforeNeighbouringHexField) {
	const auto hex64 = QString(64, QChar::fromLatin1('a'));
	const auto line = u"key_id="_q + hex64 + u" fingerprint=-123"_q;
	CHECK_EQ(ExtractKeyId(line), hex64);
}

// ExtractKeyId: when key_id carries only 63 hex digits, a space before
// the next logfmt field stops collection. Pin the exact result rather
// than only checking LooksLikeKeyId, so a regression that returns empty
// or stops early does not silently pass.
TEST_CASE(ExtractKeyIdDoesNotAbsorbNeighbouringFieldOnTruncated) {
	const auto hex63 = QString(63, QChar::fromLatin1('a'));
	const auto line = u"key_id="_q + hex63 + u" fingerprint=99"_q;
	CHECK_EQ(ExtractKeyId(line), hex63);
}

// ExtractKeyId: same as above but with a newline separator. The logfmt
// lookahead identifies fingerprint= as a field (has '=' before
// whitespace) and stops, so the absorbed 'f' bug cannot return via a
// log paste that spans two lines.
TEST_CASE(ExtractKeyIdDoesNotAbsorbNeighbouringFieldOnTruncatedNewline) {
	const auto hex63 = QString(63, QChar::fromLatin1('a'));
	const auto line = u"key_id="_q + hex63 + u"\nfingerprint=99"_q;
	CHECK_EQ(ExtractKeyId(line), hex63);
}

// ExtractKeyId: a key_id value that wraps at a terminal boundary (hex
// spans two lines) yields the same 64 digits as the single-line form.
TEST_CASE(ExtractKeyIdHandlesWrappedLogLine) {
	const auto hex32a = QString(32, QChar::fromLatin1('a'));
	const auto hex32b = QString(32, QChar::fromLatin1('b'));
	const auto wrapped = u"key_id="_q + hex32a + u"\n"_q + hex32b;
	CHECK_EQ(ExtractKeyId(wrapped), hex32a + hex32b);
}

// LooksLikeKeyId: 64 plain hex chars (no dashes) is accepted.
TEST_CASE(LooksLikeKeyIdAccepts64PlainHex) {
	const auto s = QString(64, QChar::fromLatin1('a'));
	CHECK(LooksLikeKeyId(s));
}

// LooksLikeKeyId: 79-char form (64 hex + 15 dashes, grouped by 4) is accepted.
TEST_CASE(LooksLikeKeyIdAccepts79CharForm) {
	const auto check = CheckServerKey(QString::fromLatin1(kRsa2048Spki));
	CHECK(check.valid());
	CHECK_EQ(check.identity.size(), 79);
	CHECK(LooksLikeKeyId(check.identity));
}

// LooksLikeKeyId: a value with a leading quote (logfmt unstripped) is rejected.
TEST_CASE(LooksLikeKeyIdRejectsQuotedValue) {
	CHECK(!LooksLikeKeyId(u"\"abcd\""_q));
}

// LooksLikeKeyId: anything with fewer than 64 hex digits is rejected.
TEST_CASE(LooksLikeKeyIdRejectsShortValue) {
	CHECK(!LooksLikeKeyId(u"abcd"_q));
}

// ChooseIdentityLayout: both sizes fit at 13px.
TEST_CASE(ChooseIdentityLayoutUsesSize13WhenFits) {
	const auto layout = ChooseIdentityLayout(324, 320, 300);
	CHECK_EQ(layout.pixelSize, 13);
	CHECK(layout.fits);
}

// ChooseIdentityLayout: only 12px fits, so the layout steps down.
TEST_CASE(ChooseIdentityLayoutStepsDownTo12WhenOnly12Fits) {
	const auto layout = ChooseIdentityLayout(324, 330, 320);
	CHECK_EQ(layout.pixelSize, 12);
	CHECK(layout.fits);
}

// ChooseIdentityLayout: neither size fits; fits is false.
TEST_CASE(ChooseIdentityLayoutNoFitWhenNeitherFits) {
	const auto layout = ChooseIdentityLayout(324, 330, 330);
	CHECK(!layout.fits);
}

// CheckPinnedServerConfig: the pinned endpoint fixture, valid apart
// from the dc id passed in.
[[nodiscard]] CustomServer PinnedServer(int dcId) {
	return CustomServer{
		.dcId = dcId,
		.ip = "203.0.113.10",
		.port = 443,
		.key = std::make_shared<details::RSAPublicKey>(
			CheckServerKey(QString::fromLatin1(kRsa2048Spki)).key),
	};
}

// CheckPinnedServerConfig: nothing pinned means nothing to contradict.
TEST_CASE(NoPinMeansNoConfigFailure) {
	CHECK(CheckPinnedServerConfig(2, CustomServer{}) == std::nullopt);
}

// CheckPinnedServerConfig: a server reporting the pinned dc id passes.
TEST_CASE(MatchingConfigDcIsNoFailure) {
	CHECK(CheckPinnedServerConfig(2, PinnedServer(2)) == std::nullopt);
}

// CheckPinnedServerConfig: a server naming another dc id than the pin
// is a mismatch. This is the telegramd-with-non-default-TG_DC_ID case:
// without the report the account loses its only endpoint in silence.
TEST_CASE(DifferentConfigDcIsMismatch) {
	const auto failure = CheckPinnedServerConfig(3, PinnedServer(2));
	CHECK(failure == PinnedServerFailure::DcIdMismatch);
}
