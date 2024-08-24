#include <nlohmann/json.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <stdexcept>

using json = nlohmann::json;

enum class MessageType : uint8_t { 
    HELLO
};

class MessageData {
public:
    virtual ~MessageData() = default;
    virtual MessageType type() = 0;
    virtual json to_json() = 0;
    static std::unique_ptr<MessageData> from_json(const json& j);
};

class HelloData : public MessageData {
public:
    std::string public_key;

    MessageType type();
    json to_json();

    static std::unique_ptr<HelloData> from_json(const json& j) {
        auto data = std::make_unique<HelloData>();
        j["public_key"].get_to(data->public_key);
        return data;
    }
};

class Message {
public:
    MessageType message_type;
    std::unique_ptr<MessageData> data;
    uint32_t counter;
    std::string signature;

    json to_json();

    static Message from_json(const json& j) {
        Message message;
        j["message_type"].get_to(message.message_type);

        auto type = static_cast<MessageType>(j["message_type"].get<uint8_t>());
        switch (type) {
            case MessageType::HELLO:
                message.data = HelloData::from_json(j["data"]);
                break;
            default:
                throw std::runtime_error("Unknown MessageType");
        }

        j["counter"].get_to(message.counter);
        j["signature"].get_to(message.signature);

        return message;
    }
};