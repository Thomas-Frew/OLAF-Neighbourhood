add_executable(messages messages.cpp)

target_link_libraries(messages PRIVATE nlohmann_json::nlohmann_json)