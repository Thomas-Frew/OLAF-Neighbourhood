add_executable(client main.cpp)

find_package(Threads REQUIRED)
target_link_libraries(client PRIVATE Threads::Threads)