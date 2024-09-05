#include "cli.hpp"
#include "client.hpp"
#include "connection.hpp"
#include "messagehandler.hpp"
#include <iostream>
#include <string>
#include <thread>

// Sends a WebSocket message and prints the response
int main(int argc, char **argv) {
    // Default settings
    std::string host = "localhost";
    std::string port = "1443";
    std::string public_key = "default";

    // Port is customisable
    if (argc > 1) {
        port = argv[1];
    }
    if (argc > 2) {
        public_key = argv[2];
    }
    if (argc > 3) {
        std::cerr << "Usage: client <port>? <public_key>?" << std::endl;
        return EXIT_FAILURE;
    }

    auto conn = Connection(host, port);

    // Print output while its available
    std::atomic<bool> running = true;
    std::thread output_thread([&conn, &running]() {
        MessageHandler handler;
        try {
            while (running) {
                auto message = conn.read();
                handler.handle_message(message);
            }
        } catch (std::exception const &e) {
            if (!running) {
                // graceful shutdown, do nothing
            } else {
                running = false;
                std::cerr << "Error in output thread: " << e.what()
                          << std::endl;
            }
        }
    });

    // Create a client
    Client client(public_key);

    // Begin the command-line interface
    cli(std::move(conn), std::move(client), running);

    // Close the WebSocket connection
    running = false;
    conn.close();

    // If we get here then the connection is closed gracefully
    output_thread.join();
}
