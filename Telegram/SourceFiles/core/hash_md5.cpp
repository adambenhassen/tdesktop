/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "core/utils.h"

#include <cstring>

// md5 hash, taken somewhere from the internet

namespace {

	inline void _md5_decode(uint32 *output, const uchar *input, uint32 len) {
		for (uint32 i = 0, j = 0; j < len; i++, j += 4) {
			output[i] = ((uint32)input[j]) | (((uint32)input[j + 1]) << 8) | (((uint32)input[j + 2]) << 16) | (((uint32)input[j + 3]) << 24);
		}
	}

	inline void _md5_encode(uchar *output, const uint32 *input, uint32 len) {
		for (uint32 i = 0, j = 0; j < len; i++, j += 4) {
			output[j + 0] = (input[i]) & 0xFF;
			output[j + 1] = (input[i] >> 8) & 0xFF;
			output[j + 2] = (input[i] >> 16) & 0xFF;
			output[j + 3] = (input[i] >> 24) & 0xFF;
		}
	}

	inline uint32 _md5_rotate_left(uint32 x, int n) {
		return (x << n) | (x >> (32 - n));
	}

	inline uint32 _md5_F(uint32 x, uint32 y, uint32 z) {
		return (x & y) | (~x & z);
	}

	inline uint32 _md5_G(uint32 x, uint32 y, uint32 z) {
		return (x & z) | (y & ~z);
	}

	inline uint32 _md5_H(uint32 x, uint32 y, uint32 z) {
		return x ^ y ^ z;
	}

	inline uint32 _md5_I(uint32 x, uint32 y, uint32 z) {
		return y ^ (x | ~z);
	}

	inline void _md5_FF(uint32 &a, uint32 b, uint32 c, uint32 d, uint32 x, uint32 s, uint32 ac) {
		a = _md5_rotate_left(a + _md5_F(b, c, d) + x + ac, s) + b;
	}

	inline void _md5_GG(uint32 &a, uint32 b, uint32 c, uint32 d, uint32 x, uint32 s, uint32 ac) {
		a = _md5_rotate_left(a + _md5_G(b, c, d) + x + ac, s) + b;
	}

	inline void _md5_HH(uint32 &a, uint32 b, uint32 c, uint32 d, uint32 x, uint32 s, uint32 ac) {
		a = _md5_rotate_left(a + _md5_H(b, c, d) + x + ac, s) + b;
	}

	inline void _md5_II(uint32 &a, uint32 b, uint32 c, uint32 d, uint32 x, uint32 s, uint32 ac) {
		a = _md5_rotate_left(a + _md5_I(b, c, d) + x + ac, s) + b;
	}

	static uchar _md5_padding[64] = {
		0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
}

HashMd5::HashMd5(const void *input, uint32 length) : _finalized(false) {
	init();
	if (input && length > 0) feed(input, length);
}

void HashMd5::feed(const void *input, uint32 length) {
	uint32 index = _count[0] / 8 % _md5_block_size;

	const uchar *buf = (const uchar *)input;

	if ((_count[0] += (length << 3)) < (length << 3)) {
		_count[1]++;
	}
	_count[1] += (length >> 29);

	uint32 firstpart = 64 - index;

	uint32 i;

	if (length >= firstpart) {
		memcpy(&_buffer[index], buf, firstpart);
		transform(_buffer);

		for (i = firstpart; i + _md5_block_size <= length; i += _md5_block_size) {
			transform(&buf[i]);
		}

		index = 0;
	} else {
		i = 0;
	}

	memcpy(&_buffer[index], &buf[i], length - i);
}

int32 *HashMd5::result() {
	if (!_finalized) finalize();
	return (int32*)_digest;
}

void HashMd5::init() {
	_count[0] = 0;
	_count[1] = 0;

	_state[0] = 0x67452301;
	_state[1] = 0xefcdab89;
	_state[2] = 0x98badcfe;
	_state[3] = 0x10325476;
}

void HashMd5::finalize() {
	if (!_finalized) {
		uchar bits[8];
		_md5_encode(bits, _count, 8);

		uint32 index = _count[0] / 8 % 64, paddingLen = (index < 56) ? (56 - index) : (120 - index);
		feed(_md5_padding, paddingLen);
		feed(bits, 8);

		_md5_encode(_digest, _state, 16);

		_finalized = true;
	}
}

void HashMd5::transform(const uchar *block) {
	uint32 a = _state[0], b = _state[1], c = _state[2], d = _state[3], x[16];
	_md5_decode(x, block, _md5_block_size);

	_md5_FF(a, b, c, d, x[0] , 7 , 0xd76aa478);
	_md5_FF(d, a, b, c, x[1] , 12, 0xe8c7b756);
	_md5_FF(c, d, a, b, x[2] , 17, 0x242070db);
	_md5_FF(b, c, d, a, x[3] , 22, 0xc1bdceee);
	_md5_FF(a, b, c, d, x[4] , 7 , 0xf57c0faf);
	_md5_FF(d, a, b, c, x[5] , 12, 0x4787c62a);
	_md5_FF(c, d, a, b, x[6] , 17, 0xa8304613);
	_md5_FF(b, c, d, a, x[7] , 22, 0xfd469501);
	_md5_FF(a, b, c, d, x[8] , 7 , 0x698098d8);
	_md5_FF(d, a, b, c, x[9] , 12, 0x8b44f7af);
	_md5_FF(c, d, a, b, x[10], 17, 0xffff5bb1);
	_md5_FF(b, c, d, a, x[11], 22, 0x895cd7be);
	_md5_FF(a, b, c, d, x[12], 7 , 0x6b901122);
	_md5_FF(d, a, b, c, x[13], 12, 0xfd987193);
	_md5_FF(c, d, a, b, x[14], 17, 0xa679438e);
	_md5_FF(b, c, d, a, x[15], 22, 0x49b40821);

	_md5_GG(a, b, c, d, x[1] , 5 , 0xf61e2562);
	_md5_GG(d, a, b, c, x[6] , 9 , 0xc040b340);
	_md5_GG(c, d, a, b, x[11], 14, 0x265e5a51);
	_md5_GG(b, c, d, a, x[0] , 20, 0xe9b6c7aa);
	_md5_GG(a, b, c, d, x[5] , 5 , 0xd62f105d);
	_md5_GG(d, a, b, c, x[10], 9 , 0x2441453);
	_md5_GG(c, d, a, b, x[15], 14, 0xd8a1e681);
	_md5_GG(b, c, d, a, x[4] , 20, 0xe7d3fbc8);
	_md5_GG(a, b, c, d, x[9] , 5 , 0x21e1cde6);
	_md5_GG(d, a, b, c, x[14], 9 , 0xc33707d6);
	_md5_GG(c, d, a, b, x[3] , 14, 0xf4d50d87);
	_md5_GG(b, c, d, a, x[8] , 20, 0x455a14ed);
	_md5_GG(a, b, c, d, x[13], 5 , 0xa9e3e905);
	_md5_GG(d, a, b, c, x[2] , 9 , 0xfcefa3f8);
	_md5_GG(c, d, a, b, x[7] , 14, 0x676f02d9);
	_md5_GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

	_md5_HH(a, b, c, d, x[5] , 4 , 0xfffa3942);
	_md5_HH(d, a, b, c, x[8] , 11, 0x8771f681);
	_md5_HH(c, d, a, b, x[11], 16, 0x6d9d6122);
	_md5_HH(b, c, d, a, x[14], 23, 0xfde5380c);
	_md5_HH(a, b, c, d, x[1] , 4 , 0xa4beea44);
	_md5_HH(d, a, b, c, x[4] , 11, 0x4bdecfa9);
	_md5_HH(c, d, a, b, x[7] , 16, 0xf6bb4b60);
	_md5_HH(b, c, d, a, x[10], 23, 0xbebfbc70);
	_md5_HH(a, b, c, d, x[13], 4 , 0x289b7ec6);
	_md5_HH(d, a, b, c, x[0] , 11, 0xeaa127fa);
	_md5_HH(c, d, a, b, x[3] , 16, 0xd4ef3085);
	_md5_HH(b, c, d, a, x[6] , 23, 0x4881d05);
	_md5_HH(a, b, c, d, x[9] , 4 , 0xd9d4d039);
	_md5_HH(d, a, b, c, x[12], 11, 0xe6db99e5);
	_md5_HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
	_md5_HH(b, c, d, a, x[2] , 23, 0xc4ac5665);

	_md5_II(a, b, c, d, x[0] , 6 , 0xf4292244);
	_md5_II(d, a, b, c, x[7] , 10, 0x432aff97);
	_md5_II(c, d, a, b, x[14], 15, 0xab9423a7);
	_md5_II(b, c, d, a, x[5] , 21, 0xfc93a039);
	_md5_II(a, b, c, d, x[12], 6 , 0x655b59c3);
	_md5_II(d, a, b, c, x[3] , 10, 0x8f0ccc92);
	_md5_II(c, d, a, b, x[10], 15, 0xffeff47d);
	_md5_II(b, c, d, a, x[1] , 21, 0x85845dd1);
	_md5_II(a, b, c, d, x[8] , 6 , 0x6fa87e4f);
	_md5_II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
	_md5_II(c, d, a, b, x[6] , 15, 0xa3014314);
	_md5_II(b, c, d, a, x[13], 21, 0x4e0811a1);
	_md5_II(a, b, c, d, x[4] , 6 , 0xf7537e82);
	_md5_II(d, a, b, c, x[11], 10, 0xbd3af235);
	_md5_II(c, d, a, b, x[2] , 15, 0x2ad7d2bb);
	_md5_II(b, c, d, a, x[9] , 21, 0xeb86d391);

	_state[0] += a;
	_state[1] += b;
	_state[2] += c;
	_state[3] += d;
}

int32 *hashMd5(const void *data, uint32 len, void *dest) {
	HashMd5 md5(data, len);
	memcpy(dest, md5.result(), 16);

	return (int32*)dest;
}

char *hashMd5Hex(const int32 *hashmd5, void *dest) {
	char *md5To = (char*)dest;
	const uchar *res = (const uchar*)hashmd5;

	for (int i = 0; i < 16; ++i) {
		uchar ch(res[i]), high = (ch >> 4) & 0x0F, low = ch & 0x0F;
		md5To[i * 2 + 0] = high + ((high > 0x09) ? ('a' - 0x0A) : '0');
		md5To[i * 2 + 1] = low + ((low > 0x09) ? ('a' - 0x0A) : '0');
	}

	return md5To;
}
