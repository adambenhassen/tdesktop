/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "tests/unit/system_resolver_fixture.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static const char FixtureHost[] = "system-resolver-fixture.test";
static uint32_t Answers[8];
static atomic_int AnswerCount;
static atomic_int NextAnswer;

void UnitSystemResolverSetAnswers(const uint32_t *answers, size_t count) {
	if (count > sizeof(Answers) / sizeof(Answers[0])) {
		abort();
	}
	if (count) {
		memcpy(Answers, answers, count * sizeof(Answers[0]));
	}
	atomic_store(&NextAnswer, 0);
	atomic_store(&AnswerCount, (int)count);
}

int UnitSystemResolverLookups(void) {
	return atomic_load(&NextAnswer);
}

static int UnitGetAddrInfo(
		const char *node,
		const char *service,
		const struct addrinfo *hints,
		struct addrinfo **result) {
	if (!node || strcmp(node, FixtureHost) != 0) {
		typedef int (*GetAddrInfo)(
			const char *,
			const char *,
			const struct addrinfo *,
			struct addrinfo **);
		GetAddrInfo original = (GetAddrInfo)dlsym(RTLD_NEXT, "getaddrinfo");
		return original(node, service, hints, result);
	}
	const int index = atomic_fetch_add(&NextAnswer, 1);
	if (index >= atomic_load(&AnswerCount)) {
		return EAI_NONAME;
	}
	struct addrinfo *info = calloc(1, sizeof(*info));
	struct sockaddr_in *address = calloc(1, sizeof(*address));
	if (!info || !address) {
		free(info);
		free(address);
		return EAI_MEMORY;
	}
	address->sin_family = AF_INET;
	address->sin_addr.s_addr = htonl(Answers[index]);
	info->ai_family = AF_INET;
	info->ai_socktype = hints ? hints->ai_socktype : 0;
	info->ai_addrlen = sizeof(*address);
	info->ai_addr = (struct sockaddr *)address;
	*result = info;
	return 0;
}

#ifdef __APPLE__
__attribute__((used, section("__DATA,__interpose")))
static const struct {
	const void *replacement;
	const void *replacee;
} GetAddrInfoInterpose = { UnitGetAddrInfo, getaddrinfo };
#else
int getaddrinfo(
		const char *node,
		const char *service,
		const struct addrinfo *hints,
		struct addrinfo **result) {
	return UnitGetAddrInfo(node, service, hints, result);
}
#endif
