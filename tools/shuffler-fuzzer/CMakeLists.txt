add_executable(stackshuffler
    stackshuffler.cpp
)
target_include_directories(stackshuffler PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(stackshuffler PRIVATE solidity solutil Boost::boost Boost::program_options)
