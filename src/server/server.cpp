#include "server.hpp"

// Per-socket data members
struct SocketData {};

void Server::printRecievedMessage(std::string_view message) {
    std::cout << "Recieved JSON message: " << message << std::endl;

    nlohmann::json message_json = nlohmann::json::parse(message);

    Message deserialized_message = Message::from_json(message_json);

    std::cout << "Unpacked Message Type: "
              << static_cast<uint16_t>(
                     static_cast<uint8_t>(deserialized_message.m_message_type))
              << std::endl;

    std::cout << "Unpacked Counter: "
              << static_cast<uint32_t>(deserialized_message.m_counter)
              << std::endl;

    std::cout << "Unpacked Signature: "
              << static_cast<std::string>(deserialized_message.m_signature)
              << std::endl;
}

void Server::run() {

    uWS::SSLApp app({
        .key_file_name = "ssl/server.key",
        .cert_file_name = "ssl/server.cert",
    });
    app
        // Register GET Request Handler
        .get("/*",
             [this](auto *res, auto * /*req*/) {
                 res->end("Response to any GET request.");
             })
        // Register WebSocket Message Recieved Handler (any route)
        .ws<SocketData>(
            "/*",
            {.open =
                 [](auto *ws) {
                     ws->subscribe("chat");
                     std::cout << "WebSocket connection opened" << std::endl;
                     ws->send("Connection established.", uWS::OpCode::TEXT);
                 },
             .message =
                 [this](auto *ws, std::string_view message,
                        uWS::OpCode opCode) {
                     this->printRecievedMessage(message);
                 },
             .close =
                 [](auto *ws, int code, std::string_view message) {
                     std::cout
                         << "WebSocket connection closed with code: " << code
                         << std::endl;
                 }})
        // Register Listen Handler
        .listen(m_port,
                [this](auto *listen_socket) {
                    if (listen_socket) {
                        std::cout << "Listening on port " << this->m_port
                                  << std::endl;
                    }
                })
        // Run Server
        .run();
}