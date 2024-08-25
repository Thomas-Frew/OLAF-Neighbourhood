add_executable(messages messages.cpp)

target_link_libraries(messages PRIVATE nlohmann_json::nlohmann_json)

# Clang-Format
add_custom_command(
    TARGET messages
    PRE_BUILD
    COMMAND clang-format -i ${CMAKE_SOURCE_DIR}/src/messages/*.cpp
)
