cmake_minimum_required(VERSION 3.22.1)
project(zerosploit CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------- JNI library
# Symbols are hidden by default; only the JNIEXPORT entry points in
# zs_jni.cpp are visible, which keeps the engine's internals out of reach.
add_library(zerosploit SHARED
  zs_engine.cpp
  zs_jobs.cpp
  zs_util.cpp
  zs_raw.cpp
  zs_jni.cpp)

target_compile_options(zerosploit PRIVATE
  -O2
  -fvisibility=hidden
  -ffunction-sections
  -fdata-sections
  -fno-rtti
  -fno-exceptions
  -Wall -Wextra -Wno-unused-parameter)

target_link_options(zerosploit PRIVATE -Wl,--gc-sections)
target_link_libraries(zerosploit log)

# ------------------------------------------------------------ privileged helper
# A *separate executable*, not a JNI entry point: `su` starts a new process
# with uid 0, so the app process itself can never open AF_PACKET. This binary is
# shipped inside the APK's assets and unpacked to the app's private files dir on
# first launch, then run as
#     su -c "<filesDir>/zsraw <args>"
#
# It cannot live in jniLibs: AGP only packages add_library() targets, and with
# extractNativeLibs=false the lib/ directory does not exist on disk at all, so
# there would be nothing to exec. Assets are always readable, and we copy the
# file out ourselves.
# zs_sniff.cpp holds the cleartext credential parsers. It is a separate
# translation unit rather than part of zs_helper.cpp so the host test can
# include it and exercise the parsers without the Android-only headers the
# helper needs.
add_executable(zsraw zs_helper.cpp zs_sniff.cpp zs_dns.cpp zs_tls.cpp)

target_compile_options(zsraw PRIVATE
  -O2
  -ffunction-sections
  -fdata-sections
  -fno-rtti
  -fno-exceptions
  -Wall -Wextra -Wno-unused-parameter)

# The helper is a separate process that must not depend on anything the app
# loaded. It is unpacked to filesDir, where no libc++_shared.so exists, so a
# shared STL would make it fail to start with "libc++_shared.so not found".
# ANDROID_STL is therefore c++_static for the whole project (see build.gradle):
# it costs a little APK size and removes the entire class of failure.
# ANDROID_STL is a configure-time cache variable, not a target property, which
# is why it is set from Gradle rather than here.

# Drop a copy into the generated assets dir that build.gradle registers as an
# asset source dir, so the helper is packaged for every ABI that was built.
set(ZS_ASSET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../build/generated/zsrawAssets/zsraw")
add_custom_command(TARGET zsraw POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory "${ZS_ASSET_DIR}/${ANDROID_ABI}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "$<TARGET_FILE:zsraw>" "${ZS_ASSET_DIR}/${ANDROID_ABI}/zsraw"
  COMMENT "Packaging zsraw for ${ANDROID_ABI} into assets")

# --------------------------------------------------------------------- tests
# Host-only unit tests for the packet builders (ARP / IP / TCP / ICMP / 802.11).
# Not built as part of the APK; run with tests/run_tests.sh.
option(ZS_BUILD_TESTS "Build native unit tests (host toolchain only)" OFF)
if(ZS_BUILD_TESTS)
  enable_testing()
  add_executable(zs_packet_tests tests/test_packets.cpp)
  target_include_directories(zs_packet_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME packets COMMAND zs_packet_tests)

  # Separate translation unit: zs_helper.cpp and zs_util.cpp both define
  # helpers (trim/split/J), so they cannot be included in one test.
  add_executable(zs_json_tests tests/test_json.cpp)
  target_include_directories(zs_json_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME json COMMAND zs_json_tests)

  # The service/CVE pipeline. zs_engine.cpp is included so the test can reach
  # the static tables and helpers (fingerprint internals, the version parser,
  # the OUI table). zs_util.cpp and zs_jobs.cpp are linked alongside it: the
  # first holds trim/J and the second defines Job::emit/log/progress, both of
  # which the engine's other entry points reference even though this test does
  # not call them.
  add_executable(zs_service_tests tests/test_service.cpp zs_util.cpp zs_jobs.cpp)
  target_include_directories(zs_service_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME service COMMAND zs_service_tests)
endif()
