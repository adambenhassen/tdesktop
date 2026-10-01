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
enum class LifecycleWriteForRegressionTest {
	AuthorizationSnapshot,
	CustomServerBlockMarker,
};

struct LifecycleWriteCountsForRegressionTest {
	int authorizationSnapshot = 0;
	int blockMarker = 0;
};

void RecordLifecycleWriteForRegressionTest(
	LifecycleWriteForRegressionTest operation);
void ResetLifecycleWriteCountsForRegressionTest();
[[nodiscard]] LifecycleWriteCountsForRegressionTest
GetLifecycleWriteCountsForRegressionTest();
#endif

void RunAccountLifecycleRegression(Fn<void(int)> done);

} // namespace Tests
