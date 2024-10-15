/* Created by Jack Morton and Thomas Frew, of group 48. */

#include "messages.hpp"
#include <map>
#include <nlohmann/json.hpp>
#include <string_view>

constexpr auto HelloData::type() const -> MessageType {
    return MessageType::HELLO;
}
constexpr auto PublicChatData::type() const -> MessageType {
    return MessageType::PUBLIC_CHAT;
}
constexpr auto PrivateChatData::type() const -> MessageType {
    return MessageType::PRIVATE_CHAT;
}
constexpr auto ClientListRequestData::type() const -> MessageType {
    return MessageType::CLIENT_LIST_REQUEST;
}
constexpr auto ClientListData::type() const -> MessageType {
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
    case MessageType::PRIVATE_CHAT: {
        return MessageTypeString::private_chat;
    } break;
    case MessageType::CLIENT_LIST_REQUEST: {
        return MessageTypeString::client_list_request;
    } break;
    case MessageType::CLIENT_LIST: {
        return MessageTypeString::client_list;
    } break;
    case MessageType::SIGNED_DATA: {
        return MessageTypeString::signed_data;
    } break;
    }
    throw std::runtime_error("Unknown message type");
}

auto string_to_message_type(std::string_view type) -> MessageType {
    static const auto map = std::map<std::string_view, MessageType>{
        {MessageTypeString::hello, MessageType::HELLO},
        {MessageTypeString::public_chat, MessageType::PUBLIC_CHAT},
        {MessageTypeString::private_chat, MessageType::PRIVATE_CHAT},
        {MessageTypeString::client_list_request,
         MessageType::CLIENT_LIST_REQUEST},
        {MessageTypeString::client_list, MessageType::CLIENT_LIST},
        {MessageTypeString::signed_data, MessageType::SIGNED_DATA},
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
    case MessageType::PRIVATE_CHAT:
        [[fallthrough]];
    case MessageType::PUBLIC_CHAT:
        [[fallthrough]];
    case MessageType::SIGNED_DATA:
        return true;
    }
    throw std::runtime_error("Unknown message type");
}

auto HelloData::to_json() const -> nlohmann::json {
    return nlohmann::json{{"type", message_type_to_string(this->type())},
                          {"public_key", this->m_public_key}};
}

auto HelloData::from_json(const nlohmann::json &j)
    -> std::unique_ptr<HelloData> {
    return std::make_unique<HelloData>(
        j.at("public_key").get<decltype(HelloData::m_public_key)>());
}

auto PublicChatData::to_json() const -> nlohmann::json {
    return nlohmann::json{{"type", message_type_to_string(this->type())},
                          {"sender", this->m_sender},
                          {"message", this->m_message}};
}

auto PublicChatData::from_json(const nlohmann::json &j)
    -> std::unique_ptr<PublicChatData> {
    return std::make_unique<PublicChatData>(
        j.at("sender").get<decltype(PublicChatData::m_sender)>(),
        j.at("message").get<decltype(PublicChatData::m_message)>());
}

auto ClientListRequestData::to_json() const -> nlohmann::json {
    return nlohmann::json{{"type", message_type_to_string(this->type())}};
}

auto ClientListRequestData::from_json(const nlohmann::json &j)
    -> std::unique_ptr<ClientListRequestData> {
    return std::make_unique<ClientListRequestData>();
}

auto ClientListData::to_json() const -> nlohmann::json {
    throw std::runtime_error("unimplemented");
}

auto ClientListData::from_json(const nlohmann::json &j)
    -> std::unique_ptr<ClientListData> {
    std::map<std::string, std::vector<std::string>> online_users;
    for (const auto &server : j.at("servers")) {
        online_users.emplace(
            server.at("address").get<std::string>(),
            server.at("clients").get<std::vector<std::string>>());
    }
    return std::make_unique<ClientListData>(std::move(online_users));
}

auto PrivateChatData::to_json() const -> nlohmann::json {

    nlohmann::json chat_data = nlohmann::json{
        {"participants", this->m_participants}, {"message", this->m_message}};

    return nlohmann::json{{"type", message_type_to_string(this->type())},
                          {"destination_servers", this->m_destination_servers},
                          {"iv", this->m_iv},
                          {"symm_keys", this->m_symm_keys},
                          {"chat", chat_data}};
}

auto PrivateChatData::from_json(const nlohmann::json &j)
    -> std::unique_ptr<PrivateChatData> {

    nlohmann::json chat_data = j.at("chat");

    return std::make_unique<PrivateChatData>(
        j.at("destination_servers")
            .get<decltype(PrivateChatData::m_destination_servers)>(),
        j.at("iv").get<decltype(PrivateChatData::m_iv)>(),
        j.at("symm_keys").get<decltype(PrivateChatData::m_symm_keys)>(),
        chat_data.at("participants")
            .get<decltype(PrivateChatData::m_participants)>(),
        chat_data.at("message").get<decltype(PrivateChatData::m_message)>());
}

auto Message::to_json() const -> nlohmann::json {
    if (is_signed(this->type())) {
        return nlohmann::json{
            {"type", message_type_to_string(MessageType::SIGNED_DATA)},
            {"data", this->m_data->to_json()},
            {"signature", this->m_signature},
            {"counter", this->m_counter}};
    } else {
        return this->m_data->to_json();
    }
}

auto Message::from_json(const nlohmann::json &j) -> Message {
    auto type = string_to_message_type(j.at("type").get<std::string_view>());
    if (type == MessageType::SIGNED_DATA) {
        type = string_to_message_type(
            j.at("data").at("type").get<std::string_view>());
    }

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
    case MessageType::PRIVATE_CHAT: {
        static_assert(is_signed(MessageType::PRIVATE_CHAT) == true);
        data = PrivateChatData::from_json(j.at("data"));
    } break;
    case MessageType::CLIENT_LIST_REQUEST: {
        static_assert(is_signed(MessageType::CLIENT_LIST_REQUEST) == false);
        data = ClientListRequestData::from_json(j);
    } break;
    case MessageType::CLIENT_LIST: {
        static_assert(is_signed(MessageType::CLIENT_LIST) == false);
        data = ClientListData::from_json(j);
    } break;
    case MessageType::SIGNED_DATA:
        [[fallthrough]];
    default:
        throw std::runtime_error("Invalid message");
    }

    if (!is_signed(type)) {
        return Message{type, std::move(data)};
    }

    return Message{type, std::move(data), j.at("signature").get<std::string>(),
                   j.at("counter").get<uint64_t>()};
}
