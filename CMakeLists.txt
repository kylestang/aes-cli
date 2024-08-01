cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

project(aes-cli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Catch2 3 REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/lib/ ${CMAKE_SOURCE_DIR}/include/)

# binaries
set(bin aes-cli)
add_executable(${bin} ${CMAKE_SOURCE_DIR}/app/main.cpp)
