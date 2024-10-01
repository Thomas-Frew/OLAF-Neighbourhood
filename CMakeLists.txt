cmake_minimum_required(VERSION 3.22)
project(olafs_neighbourhood)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

message(STATUS "C++ Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "C++ Compiler Version: ${CMAKE_CXX_COMPILER_VERSION}")

message(STATUS "Adding external")
add_subdirectory(external)
message(STATUS "Adding src")
add_subdirectory(src)
