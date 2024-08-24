#include "messages.hpp"
#include <App.h>
#include <cstdlib>
#include <iostream>

struct UserID {
    std::string public_key;
};

class Server {
public:
    Server(uint16_t port): m_port(port) {}

    void printRecievedMessage(std::string_view message);
    void run();

private:
    std::uint16_t m_port;
    std::vector<UserID> m_online_users;

};