cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

project(aes-cli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
# set_target_properties(libio PROPERTIES LINKER_LANGUAGE CXX)

# ciphermode
add_library(libciphermode ${CMAKE_SOURCE_DIR}/lib/crypto/ciphermode.hpp
                          ${CMAKE_SOURCE_DIR}/lib/crypto/ciphermode.cpp)

# TESTS

# io
add_executable(test_io ${CMAKE_SOURCE_DIR}/lib/io/test_io.cpp)
target_link_libraries(test_io PRIVATE Catch2::Catch2WithMain libio)

# crypto
add_executable(test_crypto ${CMAKE_SOURCE_DIR}/lib/crypto/test_crypto.cpp
                           ${CMAKE_SOURCE_DIR}/lib/crypto/crypto.cpp)
target_link_libraries(test_crypto PRIVATE Catch2::Catch2WithMain)

# ciphermode
add_executable(test_ciphermode
               ${CMAKE_SOURCE_DIR}/lib/crypto/test_ciphermode.cpp)
target_link_libraries(test_ciphermode PRIVATE Catch2::Catch2WithMain
                                              libciphermode)

# BINARY

set(bin aes-cli)
add_executable(${bin} ${CMAKE_SOURCE_DIR}/app/main.cpp)
target_link_libraries(${bin} libio libciphermode)
