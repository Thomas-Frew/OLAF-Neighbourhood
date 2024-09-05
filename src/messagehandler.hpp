#pragma once

#include "messages.hpp"
#include <string_view>

class MessageHandler {
  private:
    auto verify_message(const Message &message) const -> bool;
    auto handle_public_chat(Message &&message) const -> void;
    auto handle_client_list(Message &&message) const -> void;

  public:
    auto handle_message(std::string_view message) const noexcept -> void;
};
