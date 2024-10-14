/* Created by Jack Morton and Thomas Frew, of group 48. */

#include "cli.hpp"
#include "client.hpp"
#include "connection.hpp"
#include "messagehandler.hpp"
#include "web_connection.hpp"
#include <iostream>
#include <string>
#include <thread>

// Sends a WebSocket message and prints the response
int main(int argc, char **argv) {
    // Default settings
    std::string host = "localhost";
    std::string ws_port = "1443";
    std::string web_port = "2443";
    std::string public_key = load_key("public_key.pem");
    std::string private_key = load_key("private_key.pem");

    // Port is customisable
    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        ws_port = argv[2];
    }
    if (argc > 3) {
        web_port = argv[3];
    }
    if (argc > 4) {
        std::cerr << "Usage: client <host>? <port>? <file_hosting_port>?"
                  << std::endl;
        std::cerr << "Default behaviour: wss:://localhost:1443/, "
                     "https://localhost:2443/"
                  << std::endl;
        return EXIT_FAILURE;
    }

    auto conn = Connection(host, ws_port);
    auto web_conn = WebConnection(host, web_port);

    // Print output while its available
    std::atomic<bool> running = true;
    std::jthread output_thread([&conn, &running]() {
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
    Client client(public_key, private_key);

    // Begin the command-line interface
    cli(std::move(conn), std::move(web_conn), std::move(client), running);

    // Close the WebSocket connection
    running = false;
    conn.close();
}
