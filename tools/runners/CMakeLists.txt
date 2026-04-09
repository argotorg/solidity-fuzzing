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

# Set RPATH so runners find libevmone.so at runtime without LD_LIBRARY_PATH.
# EVMONE_LIB_DIR is auto-detected from the evmone submodule or set manually via
# cmake -DEVMONE_LIB_DIR=/path/to/evmone/build/lib
if (EVMONE_LIB_DIR)
    set_target_properties(sol_debug_runner yul_debug_runner PROPERTIES
        BUILD_RPATH "${EVMONE_LIB_DIR}"
        INSTALL_RPATH "${EVMONE_LIB_DIR}"
    )
    # If evmone is built as an external project, ensure it's built before runners
    if (TARGET evmone_external)
        add_dependencies(sol_debug_runner evmone_external)
        add_dependencies(yul_debug_runner evmone_external)
    endif()
endif()
