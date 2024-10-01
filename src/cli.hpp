#pragma once

#include "client.hpp"
#include "client_data_handler.hpp"
#include "connection.hpp"
#include "data_processing.hpp"
#include "messages.hpp"
#include "web_connection.hpp"
#include <iostream>
#include <string>

inline void cli(Connection &&connection, WebConnection &&web_connection,
                Client &&client, std::atomic<bool> &running) {
    // Send hello message upon connecting [REQUIRED BY PROTOCOL]
    {
        auto message_data = std::make_unique<HelloData>(client.getPublicKey());

        uint32_t counter = client.getCounter();

        std::string data_string =
            message_data->to_json().dump() + std::to_string(counter);
        std::string signature =
            sign_message(client.getPrivateKey(), data_string);

        Message message{MessageType::HELLO, std::move(message_data), signature,
                        counter};
        connection.write(message.to_json().dump(4));
    }

    ClientDataHandler &client_data_handler = ClientDataHandler::get_instance();

    // Register self
    {
        auto default_username =
            client_data_handler.register_client(client.getPublicKey());

        std::cout << "Registered self as: " << default_username << std::endl;

        using namespace std::literals;
        client_data_handler.update_client_username(default_username, "self"s);
    }

    // Request list of online users
    {
        Message message{MessageType::CLIENT_LIST_REQUEST,
                        std::make_unique<ClientListRequestData>()};
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
                std::make_unique<PublicChatData>(client.getIdentifier(), text);

            uint32_t counter = client.getCounter();
            std::string data_string =
                message_data->to_json().dump(4) + std::to_string(counter);
            std::string signature =
                sign_message(client.getPrivateKey(), data_string);

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
            std::vector<std::string> participants = {client.getIdentifier()};

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
            std::string data_string =
                message_data->to_json().dump(4) + std::to_string(counter);
            std::string signature =
                sign_message(client.getPrivateKey(), data_string);

            Message message{MessageType::PRIVATE_CHAT, std::move(message_data),
                            signature, counter};

            connection.write(message.to_json().dump(4));

        } else if (command == "online_list") {

            auto message_data = std::make_unique<ClientListRequestData>();

            Message message{MessageType::CLIENT_LIST_REQUEST,
                            std::move(message_data)};

            connection.write(message.to_json().dump(4));

        } else if (command == "rename") {
            std::string original_name, new_name;
            std::stringstream text_stream(text);
            text_stream >> original_name >> new_name;

            client_data_handler.update_client_username(original_name, new_name);

        } else if (command == "upload") {

            std::string filename;
            std::stringstream text_stream(text);
            text_stream >> filename;

            std::string response = web_connection.write_file(filename);
            std::cout << response << '\n';

        } else if (command == "download") {

            std::string filename;
            std::stringstream text_stream(text);
            text_stream >> filename;

            web_connection.read_file(filename);

        } else {
            using namespace std::string_view_literals;
            if (command != "help"sv) {
                std::cout << "Unknown command: " << command << "\n";
            }
            std::cout << "Known commands are:\n";
            std::cout << "\tpublic_chat [message]\tSend a message to everyone"
                         "in the neighbourhood\n";
            std::cout << "\tonline_list\tList the currently online users"
                      << std::endl;
            std::cout << "\tchat [N] [user1@hostname1] ... [userN@hostnameN] "
                         "[message]\tSend a message to certain users"
                      << std::endl;
            std::cout << "\trename [old_username] [new_username]\tRename an "
                         "existing user"
                      << std::endl;
            std::cout << "\tupload [filename]\tUpload a file to the server"
                      << std::endl;
            std::cout << "\tdownload https://[host]/[filename]\tDownload a "
                         "file from the server"
                      << std::endl;
        }
    }
}
