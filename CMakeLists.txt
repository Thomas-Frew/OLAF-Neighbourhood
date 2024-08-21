cmake_minimum_required(VERSION 3.10)
project(MyProj LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)

add_subdirectory(external)
add_subdirectory(test)
add_subdirectory(src)