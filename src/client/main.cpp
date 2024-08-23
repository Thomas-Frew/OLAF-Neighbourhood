#include "connection.hpp"
#include <iostream>
#include <print>
#include <string>
#include <thread>

// Sends a WebSocket message and prints the response
int main(int argc, char **argv) {
    // Default settings
    std::string host = "localhost";
    std::string port = "1443";

    // Port is customisable
    if (argc == 2) {
        port = argv[1];
    } else if (argc != 1) {
        std::println(std::cerr, "Usage: client <port>?");
        return EXIT_FAILURE;
    }

    auto conn = Connection(host, port);

    // Print output while its available
    bool running = true;
    std::thread output_thread([&conn, &running]() {
        try {
            while (running) {
                auto message = conn.read();
                std::println("[SERVER]: {}", message);
            }
        } catch (std::exception const &e) {
            if (!running) {
                // graceful shutdown, do nothing
            } else {
                std::println(std::cerr, "Error in output thread: {}", e.what());
            }
        }
    });

    std::string input;
    auto prompt = [&input]() { std::getline(std::cin, input); };
    // Send/receive messages from server until client quits
    for (prompt(); input != "/quit"; prompt()) {
        // Send the message
        conn.write(input);
    }

    // Close the WebSocket connection
    running = false;
    conn.close();

    // If we get here then the connection is closed gracefully
    output_thread.join();
}
