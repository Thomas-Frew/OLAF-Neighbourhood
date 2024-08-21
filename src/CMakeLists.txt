cmake_minimum_required(VERSION 3.22)
project(olafs_neighbourhood)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_subdirectory(server)
add_subdirectory(client)

add_compile_options(-Wall -Wall -Wextra -Wpedantic -Wconversion)
