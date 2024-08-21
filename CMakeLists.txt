cmake_minimum_required(VERSION 3.22)
project(olafs_neighbourhood)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

message(STATUS "C++ Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "C++ Compiler Version: ${CMAKE_CXX_COMPILER_VERSION}")

add_subdirectory(external)
add_subdirectory(test)
add_subdirectory(src)