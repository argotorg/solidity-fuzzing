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
