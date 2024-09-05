#pragma once

#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <string_view>

enum class MessageType : uint8_t {
    HELLO,
    PUBLIC_CHAT,
    CLIENT_LIST_REQUEST,
    CLIENT_LIST,
};

namespace MessageTypeString {
using namespace std::literals;
static std::string_view hello = "hello"sv;
static std::string_view public_chat = "public_chat"sv;
static std::string_view client_list_request = "client_list_request"sv;
static std::string_view client_list = "client_list"sv;
}; // namespace MessageTypeString

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

class MessageData {
  public:
    virtual ~MessageData() = default;
    virtual MessageType type() = 0;
    virtual nlohmann::json to_json() = 0;
    static std::unique_ptr<MessageData> from_json(const nlohmann::json &j);
};

class HelloData : public MessageData {
  public:
    MessageType type();
    nlohmann::json to_json();

    explicit HelloData(std::string_view public_key)
        : m_public_key(public_key) {}

    static std::unique_ptr<HelloData> from_json(const nlohmann::json &j) {
        return std::make_unique<HelloData>(
            j.at("public_key").get<std::string_view>());
    }

  private:
    std::string m_public_key;
};

class PublicChatData : public MessageData {
  public:
    MessageType type();
    nlohmann::json to_json();

    explicit PublicChatData(std::string_view public_key,
                            std::string_view message)
        : m_public_key(public_key), m_message(message) {}

    static std::unique_ptr<PublicChatData> from_json(const nlohmann::json &j) {
        return std::make_unique<PublicChatData>(
            j.at("public_key").get<std::string_view>(),
            j.at("message").get<std::string_view>());
    }

  private:
    std::string m_public_key;
    std::string m_message;
};

class ClientListRequest : public MessageData {
  public:
    MessageType type();
    nlohmann::json to_json();

    static std::unique_ptr<ClientListRequest>
    from_json(const nlohmann::json &j) {
        return std::make_unique<ClientListRequest>();
    }
};

class ClientList : public MessageData {
  public:
    MessageType type();
    nlohmann::json to_json();

    static std::unique_ptr<ClientListRequest>
    from_json(const nlohmann::json &j) {
        return std::make_unique<ClientListRequest>();
    }
};

class Message {
  public:
    nlohmann::json to_json();

    static Message from_json(const nlohmann::json &j) {
        const auto type =
            string_to_message_type(j.at("type").get<std::string_view>());

        std::unique_ptr<MessageData> data;
        switch (type) {
        case MessageType::HELLO: {
            data = HelloData::from_json(j["data"]);
        } break;
        case MessageType::PUBLIC_CHAT: {
            data = PublicChatData::from_json(j["data"]);
        } break;
        case MessageType::CLIENT_LIST_REQUEST: {
            data = ClientListRequest::from_json(j["data"]);
        } break;
        case MessageType::CLIENT_LIST: {
            data = ClientList::from_json(j["data"]);
        } break;
        default: {
            throw std::runtime_error("Unknown MessageType");
        }
        }

        return Message{type, std::move(data)};
    }

    inline auto type() const -> MessageType { return m_type; }
    inline auto data() const -> const MessageData & { return *m_data; }

  private:
    explicit Message(MessageType type, std::unique_ptr<MessageData> &&data)
        : m_type(type), m_data(std::move(data)) {}

    MessageType m_type;
    std::unique_ptr<MessageData> m_data;
};
