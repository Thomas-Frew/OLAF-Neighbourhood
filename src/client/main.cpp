#include "client.hpp"
#include "connection.hpp"
#include "messagehandler.hpp"
#include "messages.hpp"
#include <iostream>
#include <ranges>
#include <string>
#include <thread>

void cli(Connection &&connection, Client &&client, std::atomic<bool> &running) {
    // Send hello message upon connecting [REQUIRED BY PROTOCOL]
    {
        auto message_data = std::make_unique<HelloData>(client.getPublicKey());
        Message message{MessageType::HELLO, std::move(message_data)};
        connection.write(message.to_json().dump(4));
    }

    // Request list of online users
    {
        auto message_data = std::make_unique<ClientListRequest>();
        Message message{MessageType::CLIENT_LIST_REQUEST,
                        std::move(message_data)};
        connection.write(message.to_json().dump(4));
    }

    while (running) {

        std::string input;
        std::getline(std::cin, input);

        std::stringstream input_stream(input);

        std::string command;
        input_stream >> command;
        auto text = input_stream.str() |
                    std::ranges::views::drop_while(
                        [](unsigned char c) { return std::isspace(c); }) |
                    std::ranges::to<std::string>();

        if (command == "public_chat") {

            auto message_data =
                std::make_unique<PublicChatData>(client.getPublicKey(), text);

            Message message{MessageType::PUBLIC_CHAT, std::move(message_data)};

            nlohmann::json message_json = message.to_json();
            connection.write(message_json.dump(4));

        } else if (command == "online_list") {

            auto message_data = std::make_unique<ClientListRequest>();

            Message message{MessageType::CLIENT_LIST_REQUEST,
                            std::move(message_data)};

            nlohmann::json message_json = message.to_json();
            connection.write(message_json.dump(4));

        } else if (command == "quit") {
            running = false;
        }
    }
}

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
