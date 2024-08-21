add_executable(server main.cpp)
add_executable(beast_server beast_main.cpp)

add_compile_options(-luWS -lssl -lcrypto -lz -lpthread)

target_link_libraries(server uWebSockets)

find_package(Threads REQUIRED)
target_link_libraries(beast_server PRIVATE Threads::Threads)

# Clang-format
add_custom_command(
    TARGET server
    PRE_BUILD
    COMMAND clang-format -i ${CMAKE_SOURCE_DIR}/src/server/*.cpp
)

add_custom_command(
    TARGET beast_server
    PRE_BUILD
    COMMAND clang-format -i ${CMAKE_SOURCE_DIR}/src/server/*.cpp
)
