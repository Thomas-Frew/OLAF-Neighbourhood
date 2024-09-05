#include "messagehandler.hpp"
#include "messages.hpp"
#include <iostream>
#include <nlohmann/json.hpp>
#include <utility>

auto MessageHandler::handle_message(std::string_view raw_message) const noexcept
    -> void {
    std::cerr << "[MESSAGE RECEIVED] " << raw_message << std::endl;
    try {
        nlohmann::json message_json = nlohmann::json::parse(raw_message);
        Message message = Message::from_json(message_json);

        switch (message.m_message_type) {
        case MessageType::PUBLIC_CHAT: {
            this->handle_public_chat(std::move(message));
        }; break;
        case MessageType::CLIENT_LIST_REQUEST: {
            this->handle_client_list(std::move(message));
        }; break;
        case MessageType::HELLO:
            [[fallthrough]];
        default:
            break;
        }
    } catch (std::exception e) {
        // ignore invalid messages...
        std::cerr << "Unknown error: " << e.what() << std::endl;
    }
}

auto MessageHandler::handle_public_chat(Message &&message) const -> void {
    if (!this->verify_message(message)) {
        return;
    }

    std::cout << "Recieved public chat" << std::endl;
}

auto MessageHandler::handle_client_list(Message &&message) const -> void {
    if (!this->verify_message(message)) {
        return;
    }

    std::cout << "Recieved client list" << std::endl;
}

auto MessageHandler::verify_message(const Message &message) const -> bool {
    // TODO: Verify messages
    return true;
}
