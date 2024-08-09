cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
project(aes-cli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# external dependencies
find_package(Catch2 3 REQUIRED)
find_package(
  Boost
  COMPONENTS program_options
  REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

# sanitizers and build type optimization
message("-- Build configurations:")
message("\tCMAKE_BUILD_TYPE\t\t" ${CMAKE_BUILD_TYPE})
if(${CMAKE_BUILD_TYPE} STREQUAL Release)
  add_compile_options(-O3)
endif()
include(Sanitizers.cmake)
message("\tAddress sanitizer\t\t" ${ENABLE_ASAN})
message("\tUndefined behaviour sanitizer\t" ${ENABLE_UBSAN})

# LIBRARIES
include_directories(${CMAKE_SOURCE_DIR}/lib/)

# errors
add_library(errors ${CMAKE_SOURCE_DIR}/lib/errors/errors.hpp)
set_target_properties(errors PROPERTIES LINKER_LANGUAGE CXX)

# io
add_library(io ${CMAKE_SOURCE_DIR}/lib/io/io.hpp
               ${CMAKE_SOURCE_DIR}/lib/io/io.cpp)
target_include_directories(io PRIVATE ${Boost_INCLUDE_DIR})
target_link_libraries(io ${Boost_LIBRARIES} errors)

# crypto
add_library(crypto ${CMAKE_SOURCE_DIR}/lib/crypto/crypto.hpp
                   ${CMAKE_SOURCE_DIR}/lib/crypto/crypto.cpp)

# ciphermode
add_library(ciphermode ${CMAKE_SOURCE_DIR}/lib/crypto/ciphermode.hpp
                       ${CMAKE_SOURCE_DIR}/lib/crypto/ciphermode.cpp)
target_link_libraries(ciphermode crypto)

# TESTS
option(TEST "compile test binaries" OFF)
if(${TEST})
  # io
  add_executable(test_io ${CMAKE_SOURCE_DIR}/lib/io/test_io.cpp)
  target_link_libraries(test_io Catch2::Catch2WithMain io)

  # crypto
  add_executable(test_crypto ${CMAKE_SOURCE_DIR}/lib/crypto/test_crypto.cpp)
  target_link_libraries(test_crypto crypto Catch2::Catch2WithMain)

  # ciphermode
  add_executable(test_ciphermode
                 ${CMAKE_SOURCE_DIR}/lib/crypto/test_ciphermode.cpp)
  target_link_libraries(test_ciphermode Catch2::Catch2WithMain ciphermode)
endif()

# BINARY

set(bin aes-cli)
add_executable(${bin} ${CMAKE_SOURCE_DIR}/app/main.cpp)
target_link_libraries(${bin} io ciphermode crypto)
