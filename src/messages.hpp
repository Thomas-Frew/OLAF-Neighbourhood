#pragma once

#include <memory>
#include <nlohmann/json.hpp>
#include <span>
#include <string>
#include <string_view>
#include <vector>

enum class MessageType : uint8_t {
    HELLO,
    PUBLIC_CHAT,
    PRIVATE_CHAT,
    CLIENT_LIST_REQUEST,
    CLIENT_LIST,
    SIGNED_DATA,
};

namespace MessageTypeString {
using namespace std::literals;
static std::string_view hello = "hello"sv;
static std::string_view public_chat = "public_chat"sv;
static std::string_view private_chat = "chat"sv;
static std::string_view client_list_request = "client_list_request"sv;
static std::string_view client_list = "client_list"sv;
static std::string_view signed_data = "signed_data"sv;
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

    explicit HelloData(std::string public_key)
        : m_public_key(std::move(public_key)) {}

    static auto
    from_json(const nlohmann::json &j) -> std::unique_ptr<HelloData>;

  private:
    std::string m_public_key;
};

class PublicChatData : public MessageData {
  public:
    constexpr auto type() const -> MessageType;
    auto to_json() const -> nlohmann::json;

    explicit PublicChatData(std::string fingerprint, std::string message)
        : m_sender(std::move(fingerprint)), m_message(std::move(message)) {}

    static auto
    from_json(const nlohmann::json &j) -> std::unique_ptr<PublicChatData>;

    inline auto message() const noexcept -> std::string_view {
        return this->m_message;
    };

    inline auto sender() const noexcept -> std::string_view {
        return this->m_sender;
    };

    inline auto sender_ref() const noexcept -> const std::string & {
        return this->m_sender;
    };

  private:
    std::string m_sender;
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

    auto users() noexcept -> std::map<std::string, std::vector<std::string>> & {
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

    inline auto symm_keys() const noexcept -> std::vector<std::string> {
        return this->m_symm_keys;
    };

    inline auto participants() const noexcept -> std::vector<std::string> {
        return this->m_participants;
    };

    inline auto keys() const noexcept -> std::span<const std::string> {
        return this->m_symm_keys;
    }

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
    inline auto data() -> MessageData & { return *m_data; }

    inline auto signature() const -> const std::string & { return m_signature; }
    inline auto counter() const -> uint64_t { return m_counter; }

    explicit Message(MessageType type, std::unique_ptr<MessageData> &&data,
                     std::string signature, uint64_t counter)
        : m_type(type), m_data(std::move(data)), m_signature(signature),
          m_counter(counter) {}

    explicit Message(MessageType type, std::unique_ptr<MessageData> &&data)
        : m_type(type), m_data(std::move(data)) {}

  private:
    MessageType m_type;
    std::unique_ptr<MessageData> m_data;
    std::string m_signature;
    uint64_t m_counter;
};
