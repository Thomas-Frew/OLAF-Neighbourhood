#include "messages.hpp"

MessageType HelloData::type() { return MessageType::HELLO; }
MessageType PublicChatData::type() { return MessageType::PUBLIC_CHAT; }
MessageType ClientListRequest::type() {
    return MessageType::CLIENT_LIST_REQUEST;
}
MessageType ClientList::type() { return MessageType::CLIENT_LIST; }

nlohmann::json HelloData::to_json() {
    nlohmann::json j;
    j["type"] = static_cast<uint8_t>(type());
    j["public_key"] = m_public_key;
    return j;
}

nlohmann::json PublicChatData::to_json() {
    nlohmann::json j;
    j["type"] = static_cast<uint8_t>(type());
    j["public_key"] = m_public_key;
    j["message"] = m_message;
    return j;
}

nlohmann::json ClientListRequest::to_json() {
    nlohmann::json j;
    j["type"] = static_cast<uint8_t>(type());
    return j;
}

nlohmann::json ClientList::to_json() {
    throw std::runtime_error("unimplemented");
}

nlohmann::json Message::to_json() {
    nlohmann::json j;
    j["type"] = static_cast<uint8_t>(m_message_type);
    j["data"] = m_data->to_json();
    j["counter"] = m_counter;
    j["signature"] = m_signature;
    return j;
}
