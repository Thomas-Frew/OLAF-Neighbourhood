# Created by Jack Morton and Thomas Frew, of group 48.

add_executable(client main.cpp connection.cpp client.cpp messagehandler.cpp messages.cpp client_data_handler.cpp web_connection.cpp)
set_target_properties(client PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/client")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

target_link_libraries(client PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(client PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(client PRIVATE ${CURL_LIBRARIES})

# Clang-Format
add_custom_command(
    TARGET client
    PRE_BUILD
    COMMAND clang-format -i ${CMAKE_SOURCE_DIR}/src/*.?pp
)
