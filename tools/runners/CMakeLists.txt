add_executable(sol_debug_runner
    sol_debug_runner.cpp
    ${EVMHOST_CPP}
    ../ossfuzz/SolidityEvmoneInterface.cpp
)
target_link_libraries(sol_debug_runner PRIVATE evmc solidity libsolc Boost::boost Boost::program_options)

add_executable(yul_debug_runner
    yul_debug_runner.cpp
    ${EVMHOST_CPP}
    ../ossfuzz/YulEvmoneInterface.cpp
)
target_link_libraries(yul_debug_runner PRIVATE evmc yul solidity Boost::boost Boost::program_options)
