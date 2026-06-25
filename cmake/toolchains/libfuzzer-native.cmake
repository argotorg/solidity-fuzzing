# Native libFuzzer toolchain — builds the OSS-Fuzz harnesses on the host,
# without Docker.
#
# Uses clang + libc++ (-stdlib=libc++). clang + the system libstdc++ SEGVs
# inside libstdc++'s dynamic_cast (CompilerStack::parse -> ASTNode::filteredNodes)
# on essentially every input — empirically not a linker / ODR / opt-level / data
# problem, just a clang + libstdc++ RTTI incompatibility. The gcc host build/
# tree and the original clang + libc++ Docker build are both unaffected, so we
# build the fuzz world against libc++ here too.
#
# Because libc++ and libstdc++ have incompatible C++ ABIs, every C++ dependency
# that crosses the boundary must also be libc++: boost, protobuf+abseil, evmone
# and libprotobuf-mutator are all built with -stdlib=libc++ into deps/ by
# scripts/build_ossfuzz.sh and located via BOOST_ROOT / CMAKE_PREFIX_PATH /
# LPM_PREFIX / EVMONE_PREFIX. (The system libstdc++-built boost/protobuf/abseil
# packages must NOT be used.)

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

# clang/libFuzzer flags. The optimisation level is left to CMAKE_BUILD_TYPE
# (Release -> -O3 -DNDEBUG); only the stdlib / instrumentation / back-end bits
# live here:
#   * -stdlib=libc++ + libc++ hardening — see the file header.
#   * UBSan + libFuzzer coverage instrumentation.
#   * lld (bundled with clang) for fast links.
set(CMAKE_CXX_FLAGS "-stdlib=libc++ -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=undefined -fsanitize=fuzzer-no-link -fuse-ld=lld" CACHE STRING "Custom compilation flags" FORCE)
# Link the libFuzzer harnesses against libc++ as well.
set(CMAKE_EXE_LINKER_FLAGS "-stdlib=libc++ -fuse-ld=lld" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS "-stdlib=libc++ -fuse-ld=lld" CACHE STRING "" FORCE)

# Boost: link the static, libc++-built archives staged in deps/ (BOOST_ROOT is
# passed on the command line by scripts/build_ossfuzz.sh). Never fall back to the
# system libstdc++ boost packages — that would mix C++ ABIs.
set(Boost_USE_STATIC_LIBS ON CACHE BOOL "Link against static Boost libraries" FORCE)
set(Boost_NO_SYSTEM_PATHS ON CACHE BOOL "Ignore system Boost; use deps/ (libc++)" FORCE)
