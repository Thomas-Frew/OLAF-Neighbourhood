/* Created by Jack Morton and Thomas Frew, of group 48. */

#include "messagehandler.hpp"
#include "data_processing.hpp"
#include "messages.hpp"
#include <exception>
#include <iostream>
#include <nlohmann/json.hpp>
#include <utility>
#include <vector>

auto MessageHandler::handle_message(std::string_view raw_message) noexcept
    -> void {
    // std::cerr << "[MESSAGE RECEIVED] " << raw_message << std::endl; // DEBUG
    try {
        this->handle_message(
            Message::from_json(nlohmann::json::parse(raw_message)));

    } catch (const std::exception &e) {
        // ignore invalid messages...
        std::cerr << "Unknown error: " << e.what() << std::endl;
    }
}

auto MessageHandler::handle_message(Message &&message) -> void {
    switch (message.type()) {
    case MessageType::PUBLIC_CHAT: {
        this->handle_public_chat(std::move(message));
    }; break;
    case MessageType::PRIVATE_CHAT: {
        this->handle_private_chat(std::move(message));
    }; break;
    case MessageType::CLIENT_LIST: {
        this->handle_client_list(std::move(message));

        // handle any queued messages...
        this->m_save_messages = false;
        std::ranges::for_each(this->m_unhandled_messages,
                              [this](auto &&msg) -> void {
                                  this->handle_message(std::move(msg));
                              });
        this->m_unhandled_messages.clear();
        this->m_save_messages = true;
    }; break;
    case MessageType::HELLO:
        [[fallthrough]];
    case MessageType::CLIENT_LIST_REQUEST:
        [[fallthrough]];
    default:
        break;
    }
}

enum class MessageHandler::VerificationStatus {
    Verified,
    UnknownUser,
    InvalidSignature,
};

auto MessageHandler::handle_public_chat(Message &&message) -> void {
    const auto &data = static_cast<const PublicChatData &>(message.data());

    switch (this->verify_message(message, data.sender_ref())) {
    case VerificationStatus::Verified:
        break;
    case VerificationStatus::InvalidSignature:
        return;
    case VerificationStatus::UnknownUser:
        if (this->m_save_messages) {
            std::cout << "[SYSTEM] Outdated client list!" << std::endl;
            this->m_unhandled_messages.push_back(std::move(message));
        }
        return;
    }

    std::cout << "[PUBLIC_CHAT] "
              << this->m_client_data_handler.get_username(
                     std::string{data.sender()})
              << ": " << data.message() << std::endl;
}

auto MessageHandler::handle_private_chat(Message &&message) -> void {
    const auto &data = static_cast<const PrivateChatData &>(message.data());
    if (data.participants().size() != data.keys().size() + 1UZ) {
        return;
    }

    switch (this->verify_message(message, data.participants().front())) {
    case VerificationStatus::Verified:
        break;
    case VerificationStatus::InvalidSignature:
        return;
    case VerificationStatus::UnknownUser:
        if (this->m_save_messages) {
            std::cout << "[SYSTEM] Outdated client list!" << std::endl;
            this->m_unhandled_messages.push_back(std::move(message));
        }
        break;
    }

    auto encrypted_symm_keys = data.symm_keys();
    const std::string text = std::string(data.message());
    const std::string sender =
        this->m_client_data_handler.get_username(data.participants().front());

    for (auto &encrypted_symm_key : encrypted_symm_keys) {
        auto symm_key = decrypt_RSA(
            encrypted_symm_key, this->m_client_data_handler.get_private_key());

        if (!symm_key)
            continue;

        auto decrypted_text = aes_gcm_decrypt(text, *symm_key);
        std::cout << "[PRIVATE_CHAT] " << sender << ": " << decrypted_text
                  << std::endl;
        break;
    }
}

auto MessageHandler::handle_client_list(Message &&message) -> void {
    auto &data = static_cast<ClientListData &>(message.data());

    // Register users
    for (auto &[server, client_list] : data.users()) {
        for (auto &client : client_list) {
            std::string backup = client;
            try {
                // auto{client} ensures we make a copy, not needed but cool :3
                client =
                    this->m_client_data_handler.register_client(client, server);
            } catch (const std::exception &e) {
                // this might re-throw but i do not care to write this in a
                // nicer way. IF IT WORKS IT WORKS, DAMNIT!!!
                client =
                    this->m_client_data_handler.get_username(sha256(backup));
            }
        }
    }

    // Display to client
    std::cout << "[ONLINE USERS]";
    for (const auto &[server, client_list] : data.users()) {
        for (const auto &client : client_list) {
            std::cout << '\n' << client << '@' << server;
        }
    }
    std::cout << std::endl;
}

auto MessageHandler::verify_message(const Message &message,
                                    const std::string &fingerprint) const
    -> VerificationStatus {
    auto message_string =
        message.data().to_json().dump() + std::to_string(message.counter());

    try {
        if (!this->m_client_data_handler.check_counter(fingerprint,
                                                       message.counter())) {
            return VerificationStatus::InvalidSignature;
        }
        const auto &public_key =
            this->m_client_data_handler.get_pubkey_from_fingerprint(
                fingerprint);
        return verify_signature(public_key, message_string, message.signature())
                   ? VerificationStatus::Verified
                   : VerificationStatus::InvalidSignature;
    } catch (const std::exception &e) {
        return VerificationStatus::UnknownUser;
    }
}
