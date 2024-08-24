#include "messages.hpp"

MessageType HelloData::type() { return MessageType::HELLO; }

nlohmann::json HelloData::to_json() {
    nlohmann::json j;
    j["type"] = static_cast<uint8_t>(type());
    j["public_key"] = m_public_key;
    return j;
}

nlohmann::json Message::to_json() {
    nlohmann::json j;
    j["message_type"] = static_cast<uint8_t>(m_message_type);
    j["data"] = m_data->to_json();
    j["counter"] = m_counter;
    j["signature"] = m_signature;
    return j;
}

/*
int main() {
    auto hello_data = std::make_unique<HelloData>();
    hello_data->m_public_key = "my_public_key";

    Message message{MessageType::HELLO, std::move(hello_data), 123,
                    "signature"};

    nlohmann::json j = message.to_json();
    std::cout << "Packed JSON: " << j.dump(4) << std::endl;

    Message deserialized_message = Message::from_json(j);

    std::cout << "Unpacked Message Type: "
              << static_cast<uint8_t>(deserialized_message.m_message_type)
              << std::endl;
    std::cout << "Unpacked Public Key: "
              << static_cast<HelloData *>(deserialized_message.m_data.get())
                     ->m_public_key
              << std::endl;

    std::cout << "Unpacked Counter: "
              << static_cast<uint32_t>(deserialized_message.m_counter)
              << std::endl;

    std::cout << "Unpacked Signature: "
              << static_cast<std::string>(deserialized_message.m_signature)
              << std::endl;

    return 0;
}
*/