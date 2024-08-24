#include "messages.hpp"

using json = nlohmann::json;

MessageType HelloData::type() { return MessageType::HELLO; }

json HelloData::to_json() {
    json j;
    j["type"] = static_cast<uint8_t>(type());
    j["public_key"] = public_key;
    return j;
}

json Message::to_json() {
    json j;
    j["message_type"] = static_cast<uint8_t>(message_type);
    j["data"] = data->to_json();
    j["counter"] = counter;
    j["signature"] = signature;
    return j;
}

// Test
int main() {
    auto hello_data = std::make_unique<HelloData>();
    hello_data->public_key = "my_public_key";

    Message message{MessageType::HELLO, std::move(hello_data), 123,
                    "signature"};

    json j = message.to_json();
    std::cout << "Packed JSON: " << j.dump(4) << std::endl;

    Message deserialized_message = Message::from_json(j);

    std::cout << "Unpacked Message Type: "
              << static_cast<uint8_t>(deserialized_message.message_type)
              << std::endl;
    std::cout
        << "Unpacked Public Key: "
        << static_cast<HelloData *>(deserialized_message.data.get())->public_key
        << std::endl;

    std::cout << "Unpacked Counter: "
              << static_cast<uint32_t>(deserialized_message.counter)
              << std::endl;

    std::cout << "Unpacked Signature: "
              << static_cast<std::string>(deserialized_message.signature)
              << std::endl;

    return 0;
}
