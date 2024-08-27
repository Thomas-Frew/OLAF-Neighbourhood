include_directories(${CMAKE_SOURCE_DIR}/src/messages)
add_executable(server main.cpp ${CMAKE_SOURCE_DIR}/src/messages/messages.cpp server.cpp)

add_compile_options(-luWS -lssl -lcrypto -lz -lpthread)
target_link_libraries(server PRIVATE uWebSockets)
target_link_libraries(server PRIVATE nlohmann_json::nlohmann_json)

find_package(Threads REQUIRED)

# Clang-format
add_custom_command(
    TARGET server
    PRE_BUILD
    COMMAND clang-format -i ${CMAKE_SOURCE_DIR}/src/server/*.cpp
)
