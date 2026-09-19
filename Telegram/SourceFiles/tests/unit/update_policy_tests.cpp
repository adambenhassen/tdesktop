/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "core/update_policy.h"

using namespace Core;

TEST_CASE(EveryUpdaterEntryPointIsDenied) {
	CHECK(!UpdateNetworkAllowed(UpdateEntryPoint::Automatic));
	CHECK(!UpdateNetworkAllowed(UpdateEntryPoint::Periodic));
	CHECK(!UpdateNetworkAllowed(UpdateEntryPoint::Settings));
	CHECK(!UpdateNetworkAllowed(UpdateEntryPoint::CrashWindowRetry));
	CHECK(!UpdateNetworkAllowed(UpdateEntryPoint::CrashWindowGetApp));
	CHECK(!UpdateNetworkAllowed(UpdateEntryPoint::Manual));
}

TEST_CASE(ServerCannotChooseAnUpdateOrigin) {
	CHECK(!AcceptServerAutoupdatePrefix(QString()));
	CHECK(!AcceptServerAutoupdatePrefix(u"https://td.telegram.org"_q));
	CHECK(!AcceptServerAutoupdatePrefix(u"https://updates.attacker.test"_q));
}
