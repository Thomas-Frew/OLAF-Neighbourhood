#include "server.hpp"

// Debug
void Server::printRecievedMessage(std::string_view message) {
    std::cout << "Recieved JSON message: " << message << std::endl;

    nlohmann::json message_json = nlohmann::json::parse(message);

    Message deserialized_message = Message::from_json(message_json);

    std::cout << "Unpacked Message Type: "
              << static_cast<uint16_t>(
                     static_cast<uint8_t>(deserialized_message.m_message_type))
              << std::endl;

    std::cout << "Unpacked Counter: "
              << static_cast<uint32_t>(deserialized_message.m_counter)
              << std::endl;

    std::cout << "Unpacked Signature: "
              << static_cast<std::string>(deserialized_message.m_signature)
              << std::endl;
}

void Server::printOnlineUsers() {
    std::cout << "Online users: " << std::endl;
    for (auto user_id : this->m_online_users) {
        std::cout << "- " << user_id.public_key << std::endl;
    }
}

bool Server::addUser(UserID user_id) {
    if (this->m_online_users.contains(user_id))
        return false;
    this->m_online_users.insert(user_id);
    return true;
}

bool Server::removeUser(UserID user_id) {
    if (!this->m_online_users.contains(user_id))
        return false;
    this->m_online_users.erase(user_id);
    return true;
}

void Server::handleMessage(uWS::WebSocket<true, true, SocketData> *ws,
                           std::string_view message) {
    nlohmann::json message_json = nlohmann::json::parse(message);
    Message deserialized_message = Message::from_json(message_json);

    MessageType message_type = static_cast<MessageType>(
        static_cast<uint16_t>(deserialized_message.m_message_type));

    switch (message_type) {
    case MessageType::HELLO: {
        std::string public_key =
            static_cast<HelloData *>(deserialized_message.m_data.get())
                ->m_public_key;
        bool result = this->addUser(UserID(public_key));

        if (!result) {
            std::cerr << "User " << public_key << " is already online."
                      << std::endl;
        }

        // Debug
        printOnlineUsers();
        break;
    }

    case MessageType::PUBLIC_CHAT: {
        std::string public_key =
            static_cast<PublicChatData *>(deserialized_message.m_data.get())
                ->m_public_key;

        std::string message =
            static_cast<PublicChatData *>(deserialized_message.m_data.get())
                ->m_message;

        ws->publish("chat", message);
        break;
    }

    default: {
        std::cerr << "Unrecognised message type";
        break;
    }
    }
}

void Server::run() {
    uWS::SSLApp app({
        .key_file_name = "server/server.key",
        .cert_file_name = "server/server.cert",
    });
    app
        // Register GET Request Handler
        .get("/*",
             [this](auto *res, auto * /*req*/) {
                 res->end("Response to any GET request.");
             })
        // Register WebSocket Message Recieved Handler (any route)
        .ws<SocketData>(
            "/*",
            {.open =
                 [](auto *ws) {
                     ws->subscribe("chat");
                     std::cout << "WebSocket connection opened" << std::endl;
                     ws->send("Connection established.", uWS::OpCode::TEXT);
                 },
             .message =
                 [this](auto *ws, std::string_view message,
                        uWS::OpCode opCode) {
                     this->handleMessage(ws, message);
                 },
             .close =
                 [](auto *ws, int code, std::string_view message) {
                     std::cout
                         << "WebSocket connection closed with code: " << code
                         << std::endl;
                 }})
        // Register Listen Handler
        .listen(m_port,
                [this](auto *listen_socket) {
                    if (listen_socket) {
                        std::cout << "Listening on port " << this->m_port
                                  << std::endl;
                    }
                })
        // Run Server
        .run();
}