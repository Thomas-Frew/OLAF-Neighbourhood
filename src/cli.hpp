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

        uint32_t counter = client.getCounter();
        std::string signature =
            client.generateSignature(message_data->to_json().dump(), counter);

        Message message{MessageType::HELLO, std::move(message_data), signature,
                        counter};
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

            uint32_t counter = client.getCounter();
            std::string signature = client.generateSignature(
                message_data->to_json().dump(), counter);

            Message message{MessageType::PUBLIC_CHAT, std::move(message_data),
                            signature, counter};

            connection.write(message.to_json().dump(4));

        } else if (command == "private_chat" || command == "chat") {

            std::string canonical_user;
            std::stringstream text_stream(text);

            uint16_t num_users;
            text_stream >> num_users;

            std::vector<std::string> servers;
            std::vector<std::string> symm_keys;
            std::vector<std::string> participants = {client.getPublicKey()};

            for (uint16_t i = 0; i < num_users; i++) {
                text_stream >> canonical_user >> std::ws;

                size_t pos = canonical_user.find("@");
                std::string pub_key = canonical_user.substr(0, pos);
                std::string server = canonical_user.substr(pos + 1);
                std::string symm_key = "temp_key";

                servers.push_back(server);
                symm_keys.push_back(symm_key);
                participants.push_back(pub_key);
            }

            std::getline(text_stream, text);

            auto message_data = std::make_unique<PrivateChatData>(
                std::move(servers), "0", std::move(symm_keys),
                std::move(participants), text);

            uint32_t counter = client.getCounter();
            std::string signature = client.generateSignature(
                message_data->to_json().dump(), counter);

            Message message{MessageType::PRIVATE_CHAT, std::move(message_data),
                            signature, counter};

            connection.write(message.to_json().dump(4));

        } else if (command == "online_list") {

            auto message_data = std::make_unique<ClientListRequestData>();

            Message message{MessageType::CLIENT_LIST_REQUEST,
                            std::move(message_data)};

            connection.write(message.to_json().dump(4));

        } else {
            std::cerr << "Unknown command: " << command << "\n";
            std::cerr << "Known commands are:\n";
            std::cerr << "\tpublic_chat [message]\tSend a message to everyone"
                         "in the neighbourhood\n";
            std::cerr << "\tonline_list\tList the currently online users"
                      << std::endl;
            std::cerr << "\tchat [N] [user1@hostname1] ... [userN@hostnameN] "
                         "[message]\tSend a message to certain users"
                      << std::endl;
        }
    }
}
