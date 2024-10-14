/* Created by Jack Morton and Thomas Frew, of group 48. */

#pragma once

#include "client_data_handler.hpp"
#include "messages.hpp"
#include <string_view>
#include <vector>

class MessageHandler {
  public:
    MessageHandler()
        : m_save_messages(true),
          m_client_data_handler(ClientDataHandler::get_instance()) {}
    auto handle_message(std::string_view message) noexcept -> void;

  private:
    auto handle_message(Message &&message) -> void;

    enum class VerificationStatus;

    auto verify_message(const Message &message,
                        const std::string &fingerprint) const
        -> VerificationStatus;

    auto handle_public_chat(Message &&message) -> void;
    auto handle_private_chat(Message &&message) -> void;
    auto handle_client_list(Message &&message) -> void;

    std::vector<Message> m_unhandled_messages;
    bool m_save_messages;
    ClientDataHandler &m_client_data_handler;
};
