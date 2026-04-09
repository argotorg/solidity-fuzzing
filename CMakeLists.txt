cmake_minimum_required(VERSION 3.13.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(solidity-fuzzing LANGUAGES C CXX)

# Solidity requires C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Prepend our cmake/ dir so our overridden cmake modules (fmtlib, nlohmann-json,
# range-v3, submodules) are found before solidity's versions. This is needed
# because solidity's cmake modules use CMAKE_SOURCE_DIR which points to us
# (the parent project), not to solidity/.
list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_SOURCE_DIR}/cmake")

# Find Boost for our own targets (solidity finds it too but imported targets are dir-scoped)
find_package(Boost REQUIRED COMPONENTS filesystem program_options)

# Build solidity as a submodule — skip tests (they conflict with our evmc targets)
set(TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(solidity)

# evmc is defined in solidity/test/evmc/ but not built when tests are off.
# We define it ourselves since the original CMakeLists.txt uses PROJECT_SOURCE_DIR
# which doesn't work when added from a parent project.
if (NOT TARGET evmc)
    set(EVMC_DIR ${CMAKE_SOURCE_DIR}/solidity/test/evmc)
    add_library(evmc_loader STATIC ${EVMC_DIR}/loader.h ${EVMC_DIR}/loader.c)
    set_target_properties(evmc_loader PROPERTIES LINKER_LANGUAGE C POSITION_INDEPENDENT_CODE TRUE)
    target_link_libraries(evmc_loader INTERFACE ${CMAKE_DL_LIBS})
    target_include_directories(evmc_loader PUBLIC ${CMAKE_SOURCE_DIR}/solidity/test/)

    add_library(evmc INTERFACE)
    target_sources(evmc INTERFACE
        ${EVMC_DIR}/evmc.h
        ${EVMC_DIR}/evmc.hpp
        ${EVMC_DIR}/helpers.h
        ${EVMC_DIR}/utils.h
    )
    target_include_directories(evmc INTERFACE ${CMAKE_SOURCE_DIR}/solidity/test/)
    target_link_libraries(evmc INTERFACE evmc_loader)
endif()

# Include paths:
#   1. ${CMAKE_SOURCE_DIR} for our <tools/...> headers
#   2. solidity/ for <libsolidity/...>, <libyul/...>, <test/evmc/...> etc.
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/solidity)

# Our own EVMHost with fuzzing-specific extensions (m_subCallOutOfGas, m_contractCreationOrder)
set(EVMHOST_CPP ${CMAKE_SOURCE_DIR}/tools/common/EVMHost.cpp)

# Path to TestCaseReader.cpp in the solidity submodule
set(TESTCASEREADER_CPP ${CMAKE_SOURCE_DIR}/solidity/test/TestCaseReader.cpp)

# --- Build evmone from submodule (or use user-provided path) ---
# Runners load libevmone.so at runtime via dlopen. We build evmone as an
# external project and bake its lib directory into the runners' RPATH so
# LD_LIBRARY_PATH is not needed.
if (NOT EVMONE_LIB_DIR)
    if (EXISTS "${CMAKE_SOURCE_DIR}/evmone/CMakeLists.txt")
        include(ExternalProject)
        set(EVMONE_BUILD_DIR "${CMAKE_BINARY_DIR}/evmone-build")
        ExternalProject_Add(evmone_external
            SOURCE_DIR "${CMAKE_SOURCE_DIR}/evmone"
            BINARY_DIR "${EVMONE_BUILD_DIR}"
            CMAKE_ARGS
                -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                -DCMAKE_C_COMPILER_LAUNCHER=${CMAKE_C_COMPILER_LAUNCHER}
                -DCMAKE_CXX_COMPILER_LAUNCHER=${CMAKE_CXX_COMPILER_LAUNCHER}
                -DEVMONE_TESTING=OFF
            INSTALL_COMMAND ""
            BUILD_BYPRODUCTS "${EVMONE_BUILD_DIR}/lib/libevmone.so"
        )
        set(EVMONE_LIB_DIR "${EVMONE_BUILD_DIR}/lib")
        set(EVMONE_TARGET evmone_external)
    else()
        message(WARNING "evmone submodule not found and EVMONE_LIB_DIR not set. "
            "Runners will not find libevmone.so at runtime. "
            "Run: git submodule update --init evmone")
    endif()
endif()

# --- All tools (runners, AFL fuzzers, OSS-Fuzz targets, stack shuffler) ---
add_subdirectory(tools)
