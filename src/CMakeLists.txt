cmake_minimum_required(VERSION 3.22)
project(olafs_neighbourhood)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(Main main.cpp)
add_compile_options(-Wall -luWS -lssl -lcrypto -lz -lpthread -Wall -Wextra -Werror -Wpedantic -Wconversion)
target_link_libraries(Main uWebSockets)