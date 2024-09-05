add_executable(client main.cpp connection.cpp client.cpp messagehandler.cpp messages.cpp)
set_target_properties(client PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/client")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
target_link_libraries(client PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(client PRIVATE nlohmann_json::nlohmann_json)

# Clang-Format
add_custom_command(
    TARGET client
    PRE_BUILD
    COMMAND clang-format -i ${CMAKE_SOURCE_DIR}/src/*.?pp
)
