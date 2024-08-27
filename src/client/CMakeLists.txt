include_directories(${CMAKE_SOURCE_DIR}/src/messages)
add_executable(client main.cpp connection.cpp client.cpp ${CMAKE_SOURCE_DIR}/src/messages)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
target_link_libraries(client PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(client PRIVATE nlohmann_json::nlohmann_json)

# Clang-Format
add_custom_command(
    TARGET client
    PRE_BUILD
    COMMAND clang-format -i ${CMAKE_SOURCE_DIR}/src/client/*.cpp
)
