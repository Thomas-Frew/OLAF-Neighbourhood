#include "client.hpp"
#include "connection.hpp"
#include "messagehandler.hpp"
#include "messages.hpp"
#include <iostream>
#include <string>
#include <thread>

void cli(Connection &&connection, Client &&client) {
    {
        auto message_data = std::make_unique<HelloData>();
        message_data->m_public_key = client.getPublicKey();

        Message message{MessageType::HELLO, std::move(message_data),
                        client.getCounter(), "temp_signature"};

        nlohmann::json message_json = message.to_json();
        connection.write(message_json.dump(4));
    }

    {
        auto message_data = std::make_unique<ClientListRequest>();

        Message message{MessageType::CLIENT_LIST_REQUEST,
                        std::move(message_data), client.getCounter(),
                        "temp_signature"};

        nlohmann::json message_json = message.to_json();
        connection.write(message_json.dump(4));
    }

    for (;;) {

        std::string input;
        std::getline(std::cin, input);

        std::stringstream input_stream(input);

        std::string command;
        input_stream >> command;

        if (command == "public_chat") {

            std::string text;
            std::getline(input_stream, text);
            text = text.substr(1); // Trim leading whitespace

            auto message_data = std::make_unique<PublicChatData>();
            message_data->m_public_key = client.getPublicKey();
            message_data->m_message = text;

            Message message{MessageType::PUBLIC_CHAT, std::move(message_data),
                            client.getCounter(), "temp_signature"};

            nlohmann::json message_json = message.to_json();
            connection.write(message_json.dump(4));

        } else if (command == "online_list") {

            auto message_data = std::make_unique<ClientListRequest>();

            Message message{MessageType::CLIENT_LIST_REQUEST,
                            std::move(message_data), client.getCounter(),
                            "temp_signature"};

            nlohmann::json message_json = message.to_json();
            connection.write(message_json.dump(4));

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
    bool running = true;
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
                std::cerr << "Error in output thread: " << e.what()
                          << std::endl;
            }
        }
    });

    // Create a client
    Client client(public_key);

    // Begin the command-line interface
    cli(std::move(conn), std::move(client));

    // Close the WebSocket connection
    running = false;
    conn.close();

    // If we get here then the connection is closed gracefully
    output_thread.join();
}
