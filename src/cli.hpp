#pragma once

#include "client.hpp"
#include "connection.hpp"
#include "messages.hpp"
#include <iostream>
#include <string>

inline void cli(Connection &&connection, Client &&client,
                std::atomic<bool> &running) {
    // Send hello message upon connecting [REQUIRED BY PROTOCOL]
    {
        auto message_data = std::make_unique<HelloData>(client.getPublicKey());
        Message message{MessageType::HELLO, std::move(message_data)};
        connection.write(message.to_json().dump(4));
    }

    // Request list of online users
    {
        auto message_data = std::make_unique<ClientListRequestData>();
        Message message{MessageType::CLIENT_LIST_REQUEST,
                        std::move(message_data)};
        connection.write(message.to_json().dump(4));
    }

    while (running) {

        std::string input;
        std::getline(std::cin, input);
        std::stringstream input_stream(input);

        std::string command, text;
        input_stream >> command >> std::ws;
        std::getline(input_stream, text);

        if (command == "public_chat") {

            auto message_data =
                std::make_unique<PublicChatData>(client.getPublicKey(), text);

            Message message{MessageType::PUBLIC_CHAT, std::move(message_data)};

            nlohmann::json message_json = message.to_json();
            connection.write(message_json.dump(4));

        } else if (command == "chat") {

            std::vector<std::string> servers = {"localhost:1443"};
            std::vector<std::string> keys = {"Key1"};
            std::vector<std::string> part = {"default"};

            auto message_data = std::make_unique<PrivateChatData>(
                std::move(servers), "0", std::move(keys), std::move(part),
                "Hello!");

            Message message{MessageType::PRIVATE_CHAT, std::move(message_data)};

            nlohmann::json message_json = message.to_json();
            connection.write(message_json.dump(4));

        } else if (command == "online_list") {

            auto message_data = std::make_unique<ClientListRequestData>();

            Message message{MessageType::CLIENT_LIST_REQUEST,
                            std::move(message_data)};

            nlohmann::json message_json = message.to_json();
            connection.write(message_json.dump(4));

        } else {
            std::cerr << "Unknown command: " << command << "\n";
            std::cerr << "Known commands are:\n";
            std::cerr << "\tpublic_chat [message]\tSend a message to everyone "
                         "in the neighbourhood\n";
            std::cerr << "\tonline_list\tList the currently online users"
                      << std::endl;
        }
    }
}
