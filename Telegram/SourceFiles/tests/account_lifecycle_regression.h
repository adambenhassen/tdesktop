/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "base/basic_types.h"

namespace Tests {

#ifdef TDESKTOP_LIFECYCLE_REGRESSION
struct AuthStartupStateForRegressionTest final {
	uint64 userId = 0;
	int authorizationKeyCount = 0;
	bool hasStoredPin = false;
	bool pinUnknown = false;
	bool configReadable = false;
	bool configHasCustomServer = false;
	bool observed = false;
};

[[nodiscard]] bool AuthStartupRegressionSandboxIsValid();
void RecordAuthStartupStateForRegressionTest(
	uint64 userId,
	int authorizationKeyCount,
	bool hasStoredPin,
	bool pinUnknown,
	bool configReadable,
	bool configHasCustomServer);
[[nodiscard]] AuthStartupStateForRegressionTest
GetAuthStartupStateForRegressionTest();
void RunAuthStartupRegression(Fn<void(int)> done);

enum class LifecycleWriteForRegressionTest {
	AuthorizationSnapshot,
	AuthorizationFailureMarker,
	CustomServerBlockMarker,
};

struct LifecycleWriteCountsForRegressionTest {
	int authorizationSnapshot = 0;
	int authorizationFailureMarker = 0;
	int customServerBlockMarker = 0;
};

void RecordLifecycleWriteForRegressionTest(
	LifecycleWriteForRegressionTest operation);
void ResetLifecycleWriteCountsForRegressionTest();
[[nodiscard]] LifecycleWriteCountsForRegressionTest
GetLifecycleWriteCountsForRegressionTest();
#endif

void RunAccountLifecycleRegression(Fn<void(int)> done);

} // namespace Tests
