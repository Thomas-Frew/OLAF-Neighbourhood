#pragma once

#include <memory>
#include <nlohmann/json.hpp>
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

auto message_type_to_string(MessageType type) -> std::string_view;
auto string_to_message_type(std::string_view type) -> MessageType;

class MessageData {
  public:
    virtual ~MessageData() = default;
    virtual constexpr MessageType type() const = 0;
    virtual nlohmann::json to_json() const = 0;
    static std::unique_ptr<MessageData> from_json(const nlohmann::json &j);
};

class HelloData : public MessageData {
  public:
    constexpr auto type() const -> MessageType;
    auto to_json() const -> nlohmann::json;

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
    constexpr auto type() const -> MessageType;
    auto to_json() const -> nlohmann::json;

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
    constexpr auto type() const -> MessageType;
    auto to_json() const -> nlohmann::json;

    static std::unique_ptr<ClientListRequest>
    from_json(const nlohmann::json &j) {
        return std::make_unique<ClientListRequest>();
    }
};

class ClientList : public MessageData {
  public:
    constexpr auto type() const -> MessageType;
    auto to_json() const -> nlohmann::json;

    static std::unique_ptr<ClientListRequest>
    from_json(const nlohmann::json &j) {
        return std::make_unique<ClientListRequest>();
    }
};

class Message {
  public:
    auto to_json() const -> nlohmann::json;

    static auto from_json(const nlohmann::json &j) -> Message;

    inline auto type() const -> MessageType { return m_type; }
    inline auto data() const -> const MessageData & { return *m_data; }

    explicit Message(MessageType type, std::unique_ptr<MessageData> &&data)
        : m_type(type), m_data(std::move(data)) {}

  private:
    MessageType m_type;
    std::unique_ptr<MessageData> m_data;
};
