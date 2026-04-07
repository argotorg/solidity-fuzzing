# Override submodules.cmake to use solidity submodule's deps directory
set(SOLIDITY_DEPS_DIR "${CMAKE_SOURCE_DIR}/solidity/deps")

macro(initialize_submodule SUBMODULE_PATH)
	if(NOT IGNORE_VENDORED_DEPENDENCIES)
		file(GLOB submodule_contents "${SOLIDITY_DEPS_DIR}/${SUBMODULE_PATH}/*")

		if(submodule_contents)
			message(STATUS "git submodule '${SUBMODULE_PATH}' seem to be already initialized: nothing to do.")
		else()
			message(FATAL_ERROR "Submodule '${SUBMODULE_PATH}' not initialized. Please run 'git submodule update --init --recursive' from the repo root.")
		endif()
	endif()
endmacro()
