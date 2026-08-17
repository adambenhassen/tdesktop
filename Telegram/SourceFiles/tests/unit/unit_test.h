/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QString>

#include <functional>

namespace Test::Unit {

// Registers a case at static initialisation time, so adding a case is
// adding a TEST_CASE to a file that is already in the target's source
// list — there is no central list to keep in sync and forget.
struct Registrar {
	Registrar(const char *name, std::function<void()> body);
};

void Fail(const char *file, int line, const QString &what);

[[nodiscard]] QString Describe(qint64 value);
[[nodiscard]] QString Describe(quint64 value);
[[nodiscard]] QString Describe(int value);
[[nodiscard]] QString Describe(bool value);
[[nodiscard]] QString Describe(const QString &value);
[[nodiscard]] QString Describe(const std::string &value);
[[nodiscard]] QString Describe(const QByteArray &value);

} // namespace Test::Unit

#define TEST_CASE(name) \
	static void name(); \
	static const ::Test::Unit::Registrar name##Registrar(#name, name); \
	static void name()

#define CHECK(condition) \
	do { \
		if (!(condition)) { \
			::Test::Unit::Fail(__FILE__, __LINE__, u"" #condition ""_q); \
		} \
	} while (false)

// Reports both sides on failure. A round-trip test whose output is only
// "false" costs another build to find out what the value actually was.
#define CHECK_EQ(left, right) \
	do { \
		const auto &checkLeft = (left); \
		const auto &checkRight = (right); \
		if (!(checkLeft == checkRight)) { \
			::Test::Unit::Fail(__FILE__, __LINE__, u"%1 == %2, got %3 vs %4"_q \
				.arg(u"" #left ""_q) \
				.arg(u"" #right ""_q) \
				.arg(::Test::Unit::Describe(checkLeft)) \
				.arg(::Test::Unit::Describe(checkRight))); \
		} \
	} while (false)
