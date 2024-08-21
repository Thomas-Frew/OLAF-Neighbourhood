add_executable(server main.cpp)
add_compile_options(-luWS -lssl -lcrypto -lz -lpthread)
target_link_libraries(server uWebSockets)
