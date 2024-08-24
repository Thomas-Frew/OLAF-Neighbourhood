#include "messages.hpp"
#include <App.h>
#include <cstdlib>
#include <iostream>
#include <unordered_set>

struct UserID {
    std::string public_key;

    bool operator==(const UserID& other) const {
        return this->public_key == other.public_key;
    }
};

namespace std {
    template <>
    struct hash<UserID> {
        std::size_t operator()(const UserID& user_id) const {
            return std::hash<std::string>()(user_id.public_key);
        }
    };
}

class Server {
public:
    Server(uint16_t port): m_port(port) {}
    void run();

private:
    // Debug
    void printRecievedMessage(std::string_view message);
    void printOnlineUsers();

    // User management
    bool addUser(UserID user_id);
    bool removeUser(UserID user_id);

    // Messge handling
    void handleMessage(std::string_view message);
    
    std::uint16_t m_port;
    std::unordered_set<UserID> m_online_users;

};