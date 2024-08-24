#include "connection.hpp"
#include "messages.hpp"
#include <iostream>
#include <string>
#include <thread>

void cli(Connection &connection) {

    for (;;) {

        std::string input;
        std::getline(std::cin, input);

        std::stringstream input_stream(input);

        std::string command;
        input_stream >> command;

        if (command == "hello") {

            std::string public_key;
            input_stream >> public_key;

            uint32_t counter;
            input_stream >> counter;

            std::string signature;
            input_stream >> signature;

            auto message_data = std::make_unique<HelloData>();
            message_data->m_public_key = public_key;

            Message message{MessageType::HELLO, std::move(message_data),
                            counter, signature};

            nlohmann::json message_json = message.to_json();
            connection.write(message_json.dump(4));

        } else if (command == "public_chat") {
            
            // TODO: Implement public chat handler

        } else if (command == "quit") {

            return;
        }
    }
}

// Sends a WebSocket message and prints the response
int main(int argc, char **argv) {
    // Default settings
    std::string host = "localhost";
    std::string port = "1443";

    // Port is customisable
    if (argc == 2) {
        port = argv[1];
    } else if (argc != 1) {
        std::cerr << "Usage: client <port>?" << std::endl;
        return EXIT_FAILURE;
    }

    auto conn = Connection(host, port);

    // Print output while its available
    bool running = true;
    std::thread output_thread([&conn, &running]() {
        try {
            while (running) {
                auto message = conn.read();
                std::cout << "[SERVER]: " << message << std::endl;
            }
        } catch (std::exception const &e) {
            if (!running) {
                // graceful shutdown, do nothing
            } else {
                std::cerr << "Error in output thread: " << e.what()
                          << std::endl;
            }
        }
    });

    // Begin the CLI
    cli(conn);

    // Close the WebSocket connection
    running = false;
    conn.close();

    // If we get here then the connection is closed gracefully
    output_thread.join();
}
