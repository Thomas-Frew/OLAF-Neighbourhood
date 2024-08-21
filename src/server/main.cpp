#include <App.h>
#include <cstdlib>
#include <iostream>

// Per-socket data members
struct SocketData {};

int main(int argc, char **argv) {
    // Default settings
    std::string host = "localhost";
    int port = 1443;

    // Port is customisable
    if (argc == 2) {
        port = std::stoi(argv[1]);
    } else if (argc > 2) {
        std::cerr
            << "Usage: websocket-client-sync <port>\n Example: server 443\n";
        return EXIT_FAILURE;
    }

    uWS::App()
        // Register GET Request Handler
        .get("/*",
             [port](auto *res, auto * /*req*/) {
                 res->end("Response to any GET request.");
             })
        // Register WebSocket Message Recieved Hanlder (any route)
        .ws<SocketData>(
            "/*",
            {.open =
                 [](auto *ws) {
                     std::cout << "WebSocket connection opened" << std::endl;
                 },
             .message =
                 [](auto *ws, std::string_view message, uWS::OpCode opCode) {
                     std::string response =
                         "I love you, thanks for your message: " +
                         std::string(message);
                     ws->send(response, opCode);
                 },
             .close =
                 [](auto *ws, int code, std::string_view message) {
                     std::cout
                         << "WebSocket connection closed with code: " << code
                         << std::endl;
                 }})
        // Register Listen Handler
        .listen(port,
                [port](auto *listen_socket) {
                    if (listen_socket) {
                        std::cout << "Listening on port " << port << std::endl;
                    }
                })
        // Run Server
        .run();
}
