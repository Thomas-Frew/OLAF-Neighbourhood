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