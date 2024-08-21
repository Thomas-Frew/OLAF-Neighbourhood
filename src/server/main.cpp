#include <App.h>
#include <cstdlib>
#include <iostream>

struct SocketData {
    // Add any per-socket data members here if needed
};

int main()
{
    int port = std::getenv("SERVER_PORT") ? std::stoi(std::getenv("SERVER_PORT")) : 3000;

    uWS::App()
        .get("/*", [port](auto* res, auto* /*req*/) {
            res->end("Hello world!");
        })
        .ws<SocketData>("/*", { .open = [](auto* ws) { std::cout << "WebSocket connection opened" << std::endl; }, .message = [](auto* ws, std::string_view message, uWS::OpCode opCode) {
                std::cout << "Received message: " << message << std::endl;
                ws->send("Hi! :3", opCode); }, .close = [](auto* ws, int code, std::string_view message) { std::cout << "WebSocket connection closed with code: " << code << std::endl; } })
        .listen(port, [port](auto* listen_socket) {
            if (listen_socket) {
                std::cout << "Listening on port " << port << std::endl;
            }
        })
        .run();
}
