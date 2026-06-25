# Native libFuzzer toolchain — builds the OSS-Fuzz harnesses on the host,
# without Docker.
#
# This is the libc++-free sibling of libfuzzer.cmake. The only reason the
# OSS-Fuzz Docker image rebuilds boost/protobuf/evmone with `-stdlib=libc++`
# is MemorySanitizer parity for Google's infrastructure. The local fuzz build
# enables `-fsanitize=fuzzer` + UBSan only (no MSan), so libc++ buys nothing
# here. Dropping it lets us link directly against the system's libstdc++-built
# boost, protobuf and abseil instead of rebuilding the whole dependency stack.
#
# libprotobuf-mutator and evmone-standalone are the only deps still built from
# source — scripts/build_ossfuzz.sh stages them into deps/ and passes their
# locations in via LPM_PREFIX / EVMONE_PREFIX.

# Inherit default options
include("${CMAKE_CURRENT_LIST_DIR}/default.cmake")

# Use clang — libFuzzer (-fsanitize=fuzzer) is clang-only.
if (NOT CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER clang CACHE STRING "" FORCE)
endif()
if (NOT CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER clang++ CACHE STRING "" FORCE)
endif()

# Build fuzzing binaries
set(OSSFUZZ ON CACHE BOOL "Enable fuzzer build" FORCE)
# Use libfuzzer as the fuzzing back-end
set(LIB_FUZZING_ENGINE "-fsanitize=fuzzer" CACHE STRING "Use libfuzzer back-end" FORCE)
# clang/libFuzzer instrumentation flags. The optimisation level is left to
# CMAKE_BUILD_TYPE (Release -> -O3 -DNDEBUG); only the instrumentation/back-end
# bits live here.
#
# Differences from the OSS-Fuzz Docker toolchain:
#   * no libc++ (-stdlib=libc++, the libc++ include dir, _LIBCPP_HARDENING_MODE)
#     — we link the system's libstdc++-built boost/protobuf/abseil instead.
#   * lld instead of gold. Docker used gold to avoid OOM on Google's large link
#     jobs; locally lld (bundled with clang) is faster.
#
# KNOWN ISSUE (clang + libstdc++): the resulting binaries SEGV inside libstdc++'s
# dynamic_cast (CompilerStack::parse -> ASTNode::filteredNodes) on essentially
# every input. Empirically ruled out: linker (bfd/gold/lld crash identically),
# type_info ODR/visibility (symbols unique + DEFAULT), corrupt AST/RTTI data
# (object + RTTI graph verified valid), and optimisation level (call site at -O0
# still crashes). The host build/ tree (gcc + libstdc++) and the original Docker
# build (clang + libc++) are unaffected — i.e. it is a clang + libstdc++ RTTI
# incompatibility, not anything in this file.
set(CMAKE_CXX_FLAGS "-fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=undefined -fsanitize=fuzzer-no-link -fuse-ld=lld" CACHE STRING "Custom compilation flags" FORCE)
# Link against the system's static Boost archives (libboost_*.a). Unlike the
# Docker toolchain we do NOT request a static C runtime — distro Boost packages
# are built against the shared runtime and their cmake config rejects
# Boost_USE_STATIC_RUNTIME=ON.
set(BOOST_FOUND ON CACHE BOOL "" FORCE)
set(Boost_USE_STATIC_LIBS ON CACHE BOOL "Link against static Boost libraries" FORCE)
