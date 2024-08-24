#include "server.hpp"
#include <iostream>

int main(int argc, char **argv) {
    // Default settings
    std::string host = "localhost";
    std::uint16_t port = 1443;

    // Port is customisable
    if (argc == 2) {
        port = std::stoi(argv[1]);
    } else if (argc > 2) {
        std::cerr
            << "Usage: websocket-client-sync <port>\n Example: server 443\n";
        return EXIT_FAILURE;
    }

    Server server(port);
    server.run();
}
