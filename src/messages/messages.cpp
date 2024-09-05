#include "messages.hpp"

constexpr auto HelloData::type() const -> MessageType {
    return MessageType::HELLO;
}
constexpr auto PublicChatData::type() const -> MessageType {
    return MessageType::PUBLIC_CHAT;
}
constexpr auto ClientListRequest::type() const -> MessageType {
    return MessageType::CLIENT_LIST_REQUEST;
}
constexpr auto ClientList::type() const -> MessageType {
    return MessageType::CLIENT_LIST;
}

auto message_type_to_string(MessageType type) -> std::string_view {
    switch (type) {
    case MessageType::HELLO: {
        return MessageTypeString::hello;
    } break;
    case MessageType::PUBLIC_CHAT: {
        return MessageTypeString::public_chat;
    } break;
    case MessageType::CLIENT_LIST_REQUEST: {
        return MessageTypeString::client_list_request;
    } break;
    case MessageType::CLIENT_LIST: {
        return MessageTypeString::client_list;
    } break;
    }
    throw std::runtime_error("Unknown message type");
}

auto string_to_message_type(std::string_view type) -> MessageType {
    static const auto map = std::map<std::string_view, MessageType>{
        {MessageTypeString::hello, MessageType::HELLO},
        {MessageTypeString::public_chat, MessageType::PUBLIC_CHAT},
        {MessageTypeString::client_list_request,
         MessageType::CLIENT_LIST_REQUEST},
        {MessageTypeString::client_list, MessageType::CLIENT_LIST},
    };

    return map.at(type);
}

constexpr auto is_signed(MessageType type) -> bool {
    switch (type) {
    case MessageType::CLIENT_LIST:
        [[fallthrough]];
    case MessageType::CLIENT_LIST_REQUEST:
        return false;
    case MessageType::HELLO:
        [[fallthrough]];
    case MessageType::PUBLIC_CHAT:
        return true;
    }
    throw std::runtime_error("Unknown message type");
}

auto HelloData::to_json() const -> nlohmann::json {
    return nlohmann::json{{"type", message_type_to_string(this->type())},
                          {"public_key", this->m_public_key}};
}

auto PublicChatData::to_json() const -> nlohmann::json {
    return nlohmann::json{{"type", message_type_to_string(this->type())},
                          {"public_key", this->m_public_key},
                          {"message", this->m_message}};
}

auto ClientListRequest::to_json() const -> nlohmann::json {
    return nlohmann::json{{"type", message_type_to_string(this->type())}};
}

auto ClientList::to_json() const -> nlohmann::json {
    throw std::runtime_error("unimplemented");
}

auto Message::to_json() const -> nlohmann::json {
    if (is_signed(this->type())) {
        return nlohmann::json{{"type", message_type_to_string(this->type())},
                              {"data", this->m_data->to_json()},
                              {"signature", "temporary_signature"},
                              {"counter", 0}};
    } else {
        return this->m_data->to_json();
    }
}

auto Message::from_json(const nlohmann::json &j) -> Message {
    const auto type =
        string_to_message_type(j.at("type").get<std::string_view>());

    std::unique_ptr<MessageData> data;
    switch (type) {
    case MessageType::HELLO: {
        static_assert(is_signed(MessageType::HELLO) == true);
        data = HelloData::from_json(j.at("data"));
    } break;
    case MessageType::PUBLIC_CHAT: {
        static_assert(is_signed(MessageType::PUBLIC_CHAT) == true);
        data = PublicChatData::from_json(j.at("data"));
    } break;
    case MessageType::CLIENT_LIST_REQUEST: {
        static_assert(is_signed(MessageType::CLIENT_LIST_REQUEST) == false);
        data = ClientListRequest::from_json(j);
    } break;
    case MessageType::CLIENT_LIST: {
        static_assert(is_signed(MessageType::CLIENT_LIST) == false);
        data = ClientList::from_json(j);
    } break;
    }

    return Message{type, std::move(data)};
}
