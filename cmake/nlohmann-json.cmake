include(${CMAKE_SOURCE_DIR}/cmake/submodules.cmake)
initialize_submodule(nlohmann-json)

set(JSON_Install OFF CACHE INTERNAL "")
add_subdirectory(
	${SOLIDITY_DEPS_DIR}/nlohmann-json
	${CMAKE_BINARY_DIR}/deps/nlohmann-json
	EXCLUDE_FROM_ALL
)
