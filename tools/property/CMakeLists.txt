# fuzztest-based property tests.
#
# These targets are host-built (not Docker-only). They double as gtest cases
# (small budget, runs at every build / CI invocation) and as continuous
# fuzzing targets (set `FUZZTEST_FUZZ=<TestSuite>.<TestName>` at runtime).
#
# The fuzztest dependency is pulled in by the top-level CMakeLists.txt via
# FetchContent; if that integration is disabled (FUZZTEST_AVAILABLE OFF),
# this subdirectory is a no-op.

if (NOT FUZZTEST_AVAILABLE)
    message(STATUS "fuzztest not available; skipping tools/property/")
    return()
endif()

add_executable(tlsf_free_list_property
    tlsfFreeListProperty.cpp
)
target_link_libraries(tlsf_free_list_property PRIVATE
    yul
    fuzztest::fuzztest_gtest_main
)

add_executable(tarjan_scc_property
   TarjanSCCProperty.cpp
)
target_link_libraries(tarjan_scc_property PRIVATE
    yul
    fuzztest::fuzztest_gtest_main
)

# fuzztest_setup_fuzzing_flags() sets per-target compile/link flags needed
# for the libfuzzer-driver mode. Property-test mode (the default at runtime)
# doesn't strictly need them, but enabling them keeps the binary's two modes
# in sync.
if (COMMAND fuzztest_setup_fuzzing_flags)
    fuzztest_setup_fuzzing_flags()
endif()
