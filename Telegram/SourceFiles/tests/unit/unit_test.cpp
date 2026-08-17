/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "tests/unit/unit_test.h"

#include "base/integration.h"

#include <QtCore/QCoreApplication>

#include <cstdio>
#include <vector>

namespace Test::Unit {
namespace {

struct Case {
	const char *name = nullptr;
	std::function<void()> body;
};

// Function-local so registration from another translation unit cannot
// run before the container is constructed.
std::vector<Case> &Cases() {
	static auto result = std::vector<Case>();
	return result;
}

int CurrentFailures = 0;
int TotalFailures = 0;

// The code under test logs through base::Integration, and lib_base's
// LogWriteDebug asserts when it is missing. Swallow the output: a
// deserialization case deliberately feeds bad input and its LOG() lines
// are noise, not results.
class Integration final : public base::Integration {
public:
	using base::Integration::Integration;

	void enterFromEventLoop(FnMut<void()> &&method) override {
		method();
	}
	bool logSkipDebug() override {
		return true;
	}
	void logMessageDebug(const QString &message) override {
	}
	void logMessage(const QString &message) override {
	}
};

} // namespace

Registrar::Registrar(const char *name, std::function<void()> body) {
	Cases().push_back({ name, std::move(body) });
}

void Fail(const char *file, int line, const QString &what) {
	++CurrentFailures;
	++TotalFailures;
	std::fprintf(
		stderr,
		"    %s:%d: %s\n",
		file,
		line,
		what.toUtf8().constData());
}

QString Describe(qint64 value) {
	return QString::number(value);
}

QString Describe(quint64 value) {
	return QString::number(value);
}

QString Describe(int value) {
	return QString::number(value);
}

QString Describe(bool value) {
	return value ? u"true"_q : u"false"_q;
}

QString Describe(const QString &value) {
	return '"' + value + '"';
}

QString Describe(const std::string &value) {
	return Describe(QString::fromStdString(value));
}

QString Describe(const QByteArray &value) {
	return u"%1 bytes: %2"_q
		.arg(value.size())
		.arg(QString::fromLatin1(value.toHex()));
}

} // namespace Test::Unit

int main(int argc, char *argv[]) {
	auto app = QCoreApplication(argc, argv);
	auto integration = Test::Unit::Integration(argc, argv);
	base::Integration::Set(&integration);

	auto failed = 0;
	auto &cases = Test::Unit::Cases();

	// Registration is a side effect of a file being in the target's source
	// list, so dropping that file — an edit, a bad conflict resolution —
	// leaves a binary that builds, runs nothing and exits 0. That is a
	// green tick with no coverage behind it, which is worse than no
	// harness at all, so having no cases is itself a failure.
	if (cases.empty()) {
		std::fprintf(
			stderr,
			"No test cases registered. The binary built but covers "
			"nothing — check the source list in tests_unit.cmake.\n");
		return 1;
	}

	for (const auto &entry : cases) {
		Test::Unit::CurrentFailures = 0;
		// Named before it runs rather than after it returns: an Expects or
		// Assert inside the code under test aborts the process, and that
		// is precisely when the log has to say which case was in flight.
		std::fprintf(stderr, "run  %s\n", entry.name);
		entry.body();
		if (Test::Unit::CurrentFailures) {
			++failed;
			std::fprintf(stderr, "FAIL %s\n", entry.name);
		} else {
			std::fprintf(stderr, "ok   %s\n", entry.name);
		}
	}
	std::fprintf(
		stderr,
		"\n%d case(s), %d failed, %d failed check(s).\n",
		int(cases.size()),
		failed,
		Test::Unit::TotalFailures);
	return failed ? 1 : 0;
}
