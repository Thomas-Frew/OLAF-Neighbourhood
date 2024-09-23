#pragma once

#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

enum class MessageType : uint8_t {
    HELLO,
    PUBLIC_CHAT,
    PRIVATE_CHAT,
    CLIENT_LIST_REQUEST,
    CLIENT_LIST,
};

namespace MessageTypeString {
using namespace std::literals;
static std::string_view hello = "hello"sv;
static std::string_view public_chat = "public_chat"sv;
static std::string_view private_chat = "chat"sv;
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

    static auto
    from_json(const nlohmann::json &j) -> std::unique_ptr<HelloData>;

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

    static auto
    from_json(const nlohmann::json &j) -> std::unique_ptr<PublicChatData>;

    inline auto message() const noexcept -> std::string_view {
        return this->m_message;
    };

    inline auto public_key() const noexcept -> std::string_view {
        return this->m_public_key;
    };

  private:
    std::string m_public_key;
    std::string m_message;
};

class ClientListRequestData : public MessageData {
  public:
    constexpr auto type() const -> MessageType;
    auto to_json() const -> nlohmann::json;

    static auto from_json(const nlohmann::json &j)
        -> std::unique_ptr<ClientListRequestData>;
};

class ClientListData : public MessageData {
  public:
    constexpr auto type() const -> MessageType;
    auto to_json() const -> nlohmann::json;

    explicit ClientListData(
        std::map<std::string, std::vector<std::string>> &&online_list)
        : m_online_list(std::move(online_list)) {}

    static auto
    from_json(const nlohmann::json &j) -> std::unique_ptr<ClientListData>;

    auto users() const noexcept
        -> const std::map<std::string, std::vector<std::string>> & {
        return this->m_online_list;
    }

  private:
    std::map<std::string, std::vector<std::string>> m_online_list;
};

class PrivateChatData : public MessageData {
  public:
    constexpr auto type() const -> MessageType;
    auto to_json() const -> nlohmann::json;

    explicit PrivateChatData(std::vector<std::string> &&destination_servers,
                             std::string iv,
                             std::vector<std::string> &&symm_keys,
                             std::vector<std::string> &&participants,
                             std::string message)
        : m_destination_servers(std::move(destination_servers)), m_iv(iv),
          m_symm_keys(std::move(symm_keys)),
          m_participants(std::move(participants)), m_message(message) {}

    static auto
    from_json(const nlohmann::json &j) -> std::unique_ptr<PrivateChatData>;

    inline auto message() const noexcept -> std::string_view {
        return this->m_message;
    };

    inline auto participants() const noexcept -> std::vector<std::string> {
        return this->m_participants;
    };

  private:
    std::vector<std::string> m_destination_servers;
    std::string m_iv;
    std::vector<std::string> m_symm_keys;
    std::vector<std::string> m_participants;
    std::string m_message;
};

class Message {
  public:
    auto to_json() const -> nlohmann::json;

    static auto from_json(const nlohmann::json &j) -> Message;

    inline auto type() const -> MessageType { return m_type; }
    inline auto data() const -> const MessageData & { return *m_data; }

    explicit Message(MessageType type, std::unique_ptr<MessageData> &&data,
                     std::string_view signature, uint32_t counter)
        : m_type(type), m_data(std::move(data)), m_signature(signature),
          m_counter(counter) {}

    explicit Message(MessageType type, std::unique_ptr<MessageData> &&data)
        : Message(type, std::move(data), "No Signature", 0) {}

  private:
    MessageType m_type;
    std::unique_ptr<MessageData> m_data;
    std::string_view m_signature;
    uint32_t m_counter;
};
