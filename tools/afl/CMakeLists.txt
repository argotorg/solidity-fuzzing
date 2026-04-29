add_executable(solfuzzer
    solfuzzer.cpp
    ../common/fuzzer_common.cpp
)
target_link_libraries(solfuzzer PRIVATE libsolc evmasm Boost::boost Boost::program_options)

add_executable(const_opt_runner
    const_opt_runner.cpp
    ../common/fuzzer_common.cpp
)
target_link_libraries(const_opt_runner PRIVATE libsolc evmasm Boost::boost Boost::program_options)

# AFL harness: differential compile/deploy/execute via EVMOne, abort() on diff.
# Mirrors the sol_proto_ossfuzz_evmone pipeline but reads .sol from a file
# argument (AFL's @@) or stdin instead of a libFuzzer-supplied protobuf.
add_executable(sol_afl_diff_runner
    sol_afl_diff_runner.cpp
    ${EVMHOST_CPP}
    ../ossfuzz/SolidityEvmoneInterface.cpp
    ../ossfuzz/FuzzerDiffCommon.cpp
)
target_link_libraries(sol_afl_diff_runner PRIVATE evmc solidity libsolc Boost::boost)

if (NOT EVMONE_BUILD_SHARED)
    # Static evmone (AFL build): link the standalone archive directly so
    # AFL coverage instrumentation reaches inside the EVM. EVMHost picks up
    # the static factory via -DEVMONE_STATIC.
    target_compile_definitions(sol_afl_diff_runner PRIVATE EVMONE_STATIC)
    target_link_libraries(sol_afl_diff_runner PRIVATE
        ${EVMONE_LIB_DIR}/libevmone-standalone.a)
    if (TARGET evmone_external)
        add_dependencies(sol_afl_diff_runner evmone_external)
    endif()
elseif (EVMONE_LIB_DIR)
    # Shared evmone path (would only matter if this harness were ever built
    # outside an AFL tree). Same RPATH dance as tools/runners.
    set_target_properties(sol_afl_diff_runner PROPERTIES
        BUILD_RPATH "${EVMONE_LIB_DIR}"
        INSTALL_RPATH "${EVMONE_LIB_DIR}"
    )
    if (TARGET evmone_external)
        add_dependencies(sol_afl_diff_runner evmone_external)
    endif()
endif()
