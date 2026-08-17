# This file is part of Telegram Desktop,
# the official desktop application for the Telegram messaging service.
#
# For license and copyright information please follow this link:
# https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL

# A console test binary for the parts of the client that can be checked
# without a display or a server. It links the same td_mtproto objects the
# application does, so the code under test is the shipped code, and it
# adds only its own few translation units to the build.
#
# Kept apart from cmake/tests.cmake: that one builds test_text, a windowed
# app a human looks at, and is off by default. This one has to run
# unattended in CI, so it is always built.

add_executable(test_unit)
init_target(test_unit "(tests)")

target_include_directories(test_unit PRIVATE ${src_loc})

nice_target_sources(test_unit ${src_loc}
PRIVATE
    tests/unit/logs_stub.cpp
    tests/unit/mtproto_dc_options_tests.cpp
    tests/unit/unit_test.cpp
    tests/unit/unit_test.h

    storage/serialize_common.cpp
    storage/serialize_common.h
)

target_link_libraries(test_unit
PRIVATE
    tdesktop::td_mtproto
    tdesktop::td_scheme
    desktop-app::lib_base
    desktop-app::lib_tl
    desktop-app::external_qt
    desktop-app::external_openssl
    desktop-app::external_zlib
)

