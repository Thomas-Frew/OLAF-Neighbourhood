add_executable(client main.cpp)

find_package(Threads REQUIRED)
target_link_libraries(client PRIVATE Threads::Threads)

# Clang-Format
add_custom_command(
    TARGET client
    PRE_BUILD
    COMMAND clang-format -i ${CMAKE_SOURCE_DIR}/src/client/*.cpp
)
