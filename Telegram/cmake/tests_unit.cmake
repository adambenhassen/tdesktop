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

# The mtproto headers are written expecting this prelude — scheme.h, rpl,
# crl — because every target that compiles them has it precompiled. A test
# including mtproto_dc_options.h without it fails on MTPDdcOption. Reuse
# td_mtproto's own header rather than adding includes to app files.
target_precompile_headers(test_unit PRIVATE ${src_loc}/mtproto/mtproto_pch.h)

nice_target_sources(test_unit ${src_loc}
PRIVATE
    tests/unit/logs_stub.cpp
    tests/unit/mtproto_custom_server_input_tests.cpp
    tests/unit/mtproto_dc_options_tests.cpp
    tests/unit/mtp_instance_tests.cpp
    tests/unit/unit_test.cpp
    tests/unit/unit_test.h
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

# Put it beside Telegram in out/<config>/ instead of the target's own
# binary dir, so one documented path finds it. The generator appends the
# config, as it does for the application.
set_target_properties(test_unit PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

