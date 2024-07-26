cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

project(aes-cli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Catch2 3 REQUIRED)

option(DEBUG "debug mode" 1)

if(${DEBUG})
  message("Build type: Debug")
  set(CMAKE_BUILD_TYPE Debug)
  add_compile_options(-Wall -Werror)
else()
  message("Build type: Release")
  set(CMAKE_BUILD_TYPE Release)
endif()

include_directories(${CMAKE_SOURCE_DIR}/lib/)

# binaries
set(bin aes-cli)
add_executable(${bin} ${CMAKE_SOURCE_DIR}/app/main.cpp)

# tests
if (${DEBUG})
set(test_padding test_padding)
add_executable(test_padding ${CMAKE_SOURCE_DIR}/tests/test_padding.cpp)
target_link_libraries(${test_padding} PRIVATE Catch2::Catch2WithMain)
endif()
