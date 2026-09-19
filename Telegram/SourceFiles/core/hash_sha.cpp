/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/utils.h"

extern "C" {
#include <openssl/sha.h>
} // extern "C"

int32 *hashSha1(const void *data, uint32 len, void *dest) {
	return (int32*)SHA1((const uchar*)data, (size_t)len, (uchar*)dest);
}

int32 *hashSha256(const void *data, uint32 len, void *dest) {
	return (int32*)SHA256((const uchar*)data, (size_t)len, (uchar*)dest);
}
