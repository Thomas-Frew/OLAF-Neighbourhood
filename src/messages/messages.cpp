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

    MessageType type() {
        return MessageType::HELLO;
    }

    json to_json() {
        json j;
        j["type"] = static_cast<uint8_t>(type());
        j["public_key"] = public_key;
        return j;
    }

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

    json to_json() {
        json j;
        j["message_type"] = static_cast<uint8_t>(message_type);
        j["data"] = data->to_json();
        j["counter"] = counter;
        j["signature"] = signature;
        return j;
    }

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

// Test
int main() {
    auto hello_data = std::make_unique<HelloData>();
    hello_data->public_key = "my_public_key";

    Message message{MessageType::HELLO, std::move(hello_data), 123, "signature"};

    json j = message.to_json();
    std::cout << "Packed JSON: " << j.dump(4) << std::endl;

    Message deserialized_message = Message::from_json(j);
    std::cout << "Unpacked Message Type: " << static_cast<uint8_t>(deserialized_message.message_type) << std::endl;
    std::cout << "Unpacked Public Key: " << static_cast<HelloData*>(deserialized_message.data.get())->public_key << std::endl;
    std::cout << "Unpacked Counter: " << static_cast<uint32_t>(deserialized_message.counter) << std::endl;
    std::cout << "Unpacked Signature: " << static_cast<std::string>(deserialized_message.signature) << std::endl;

    return 0;
}
