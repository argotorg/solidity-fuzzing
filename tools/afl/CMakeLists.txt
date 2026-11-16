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

# AFL harness: one binary per oracle mode (see s_configs in sol_afl_diff_runner.cpp).
function(add_afl_runner name)
    add_executable(${name}
        sol_afl_diff_runner.cpp
        AflExecution.cpp
        ${EVMHOST_CPP}
        ../ossfuzz/SolidityEvmoneInterface.cpp
        ../ossfuzz/FuzzerDiffCommon.cpp
    )
    target_link_libraries(${name} PRIVATE evmc solidity libsolc Boost::boost)
    if (ARGN)
        target_compile_definitions(${name} PRIVATE ${ARGN})
    endif()
    if (NOT EVMONE_BUILD_SHARED)
        # Static evmone (AFL build) so coverage instrumentation reaches inside the EVM.
        target_compile_definitions(${name} PRIVATE EVMONE_STATIC)
        target_link_libraries(${name} PRIVATE ${EVMONE_LIB_DIR}/libevmone-standalone.a)
    elseif (EVMONE_LIB_DIR)
        set_target_properties(${name} PROPERTIES BUILD_RPATH "${EVMONE_LIB_DIR}" INSTALL_RPATH "${EVMONE_LIB_DIR}")
    endif()
    if (TARGET evmone_external)
        add_dependencies(${name} evmone_external)
    endif()
endfunction()

add_afl_runner(sol_afl_diff_runner)                                  # legacy vs legacy-opt
add_afl_runner(sol_afl_diff_runner_viair AFL_MODE_VIAIR)             # legacy-opt vs ir-opt
add_afl_runner(sol_afl_diff_runner_viair_opt AFL_MODE_VIAIR_OPT)     # ir vs ir-opt
add_afl_runner(sol_afl_diff_runner_ssacfg AFL_MODE_SSACFG)           # ir-opt vs ssacfg-opt
add_afl_runner(sol_afl_diff_runner_optseq AFL_MODE_OPTSEQ)           # ir-opt vs ir-opt, input-drawn Yul steps + runs
add_afl_runner(sol_afl_diff_runner_evmversion AFL_MODE_EVMVERSION)   # ir-opt: current EVM vs paris
add_afl_runner(sol_afl_diff_runner_metamorphic AFL_MODE_METAMORPHIC) # ir-opt vs ir-opt of identity-wrapped source
add_afl_runner(sol_afl_ice_runner AFL_MODE_ICE)                      # compile only, ICEs escape
