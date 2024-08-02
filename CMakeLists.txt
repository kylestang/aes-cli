cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

project(aes-cli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Catch2 3 REQUIRED)
FIND_PACKAGE(Boost COMPONENTS program_options REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/lib/)
include_directories(${Boost_INCLUDE_DIRS})

# libraries
add_library(libio ${CMAKE_SOURCE_DIR}/lib/io/io.hpp)
target_include_directories(libio PRIVATE ${Boost_INCLUDE_DIR})
target_link_libraries(libio PRIVATE ${Boost_LIBRARIES})
set_target_properties(libio PROPERTIES LINKER_LANGUAGE CXX)

# binaries
set(bin aes-cli)
add_executable(${bin} ${CMAKE_SOURCE_DIR}/app/main.cpp)
target_link_libraries(${bin} libio)
