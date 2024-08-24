#include <nlohmann/json.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <stdexcept>

enum class MessageType : uint8_t { 
    HELLO
};

class MessageData {
public:
    virtual ~MessageData() = default;
    virtual MessageType type() = 0;
    virtual nlohmann::json to_json() = 0;
    static std::unique_ptr<MessageData> from_json(const nlohmann::json& j);
};

class HelloData : public MessageData {
public:
    std::string m_public_key;

    MessageType type();
    nlohmann::json to_json();

    static std::unique_ptr<HelloData> from_json(const nlohmann::json& j) {
        auto data = std::make_unique<HelloData>();
        j["public_key"].get_to(data->m_public_key);
        return data;
    }
};

class Message {
public:
    MessageType m_message_type;
    std::unique_ptr<MessageData> m_data;
    uint32_t m_counter;
    std::string m_signature;

    nlohmann::json to_json();

    static Message from_json(const nlohmann::json& j) {
        Message message;
        j["message_type"].get_to(message.m_message_type);

        auto type = static_cast<MessageType>(j["message_type"].get<uint8_t>());
        switch (type) {
            case MessageType::HELLO:
                message.m_data = HelloData::from_json(j["data"]);
                break;
            default:
                throw std::runtime_error("Unknown MessageType");
        }

        j["counter"].get_to(message.m_counter);
        j["signature"].get_to(message.m_signature);

        return message;
    }
};