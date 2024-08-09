cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

project(aes-cli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Catch2 3 REQUIRED)
find_package(
  Boost
  COMPONENTS program_options
  REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/lib/)
include_directories(${Boost_INCLUDE_DIRS})

# LIBRARIES

# io
add_library(libio ${CMAKE_SOURCE_DIR}/lib/io/io.hpp
                  ${CMAKE_SOURCE_DIR}/lib/io/io.cpp)
target_include_directories(libio PRIVATE ${Boost_INCLUDE_DIR})
target_link_libraries(libio PRIVATE ${Boost_LIBRARIES})
set_target_properties(libio PROPERTIES LINKER_LANGUAGE CXX)
# test bin
add_executable(test_io ${CMAKE_SOURCE_DIR}/lib/io/test_io.cpp)
target_link_libraries(test_io PRIVATE Catch2::Catch2WithMain libio)

# padding
add_library(libpadding ${CMAKE_SOURCE_DIR}/lib/crypto/padding.hpp)
set_target_properties(libpadding PROPERTIES LINKER_LANGUAGE CXX)
# test bin
add_executable(test_padding ${CMAKE_SOURCE_DIR}/lib/crypto/test_padding.cpp)
target_link_libraries(test_padding PRIVATE Catch2::Catch2WithMain libpadding)

# BINARY

set(bin aes-cli)
add_executable(${bin} ${CMAKE_SOURCE_DIR}/app/main.cpp)
target_link_libraries(${bin} libio libpadding)
