/* Created by Jack Morton and Thomas Frew, of group 48. */

#pragma once

#include "client.hpp"
#include "client_data_handler.hpp"
#include "connection.hpp"
#include "data_processing.hpp"
#include "messages.hpp"
#include "web_connection.hpp"
#include <iostream>
#include <string>

inline void cli(Connection &connection, WebConnection &web_connection,
                Client &client, std::atomic<bool> &running) {
    // Send hello message upon connecting [REQUIRED BY PROTOCOL]
    {
        auto message_data = std::make_unique<HelloData>(client.getPublicKey());

        auto counter = client.getCounter();

        auto data_string =
            message_data->to_json().dump() + std::to_string(counter);
        auto signature = sign_message(client.getPrivateKey(), data_string);

        Message message{MessageType::HELLO, std::move(message_data), signature,
                        counter};
        connection.write(message.to_json().dump());
    }

    auto &client_data_handler = ClientDataHandler::get_instance();
    client_data_handler.set_private_key(client.getPrivateKey());

    // Register self
    {
        auto default_username = client_data_handler.register_client(
            client.getPublicKey(), connection.get_host());

        using namespace std::literals;
        client_data_handler.update_client_username(default_username, "self"s);
    }

    // Request list of online users
    {
        Message message{MessageType::CLIENT_LIST_REQUEST,
                        std::make_unique<ClientListRequestData>()};
        connection.write(message.to_json().dump());
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

            auto counter = client.getCounter();
            auto data_string =
                message_data->to_json().dump() + std::to_string(counter);
            auto signature = sign_message(client.getPrivateKey(), data_string);

            Message message{MessageType::PUBLIC_CHAT, std::move(message_data),
                            signature, counter};

            connection.write(message.to_json().dump());

        } else if (command == "private_chat" || command == "chat") {

            std::stringstream text_stream(text);

            uint16_t num_users;
            text_stream >> num_users;

            std::vector<std::string> servers;
            std::vector<std::string> symm_keys;
            std::vector<std::string> participants = {client.getIdentifier()};

            std::string base_symm_key = generate_random_AES_key();

            for (uint16_t i = 0; i < num_users; i++) {
                std::string username;
                text_stream >> username >> std::ws;

                servers.push_back(
                    client_data_handler.get_server_from_username(username));

                std::string symm_key = encrypt_RSA(
                    base_symm_key,
                    client_data_handler.get_pubkey_from_username(username));

                symm_keys.push_back(symm_key);
                participants.push_back(username);
            }

            std::getline(text_stream, text);
            text = aes_gcm_encrypt(text, base_symm_key);

            auto message_data = std::make_unique<PrivateChatData>(
                std::move(servers), "0", std::move(symm_keys),
                std::move(participants), text);

            uint32_t counter = client.getCounter();
            std::string data_string =
                message_data->to_json().dump() + std::to_string(counter);
            std::string signature =
                sign_message(client.getPrivateKey(), data_string);

            Message message{MessageType::PRIVATE_CHAT, std::move(message_data),
                            signature, counter};

            connection.write(message.to_json().dump());

        } else if (command == "online_list") {

            auto message_data = std::make_unique<ClientListRequestData>();

            Message message{MessageType::CLIENT_LIST_REQUEST,
                            std::move(message_data)};

            connection.write(message.to_json().dump());

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
            std::cout << "\tchat [N] [user1] ... [userN] "
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
