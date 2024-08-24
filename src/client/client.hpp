#include <cstdint>
#include <string>

class Client {
public:
    Client(std::string public_key): m_public_key(public_key) {}

    std::string getPublicKey();
    uint32_t getCounter();

    void run();

private:
    std::string m_public_key;
    uint32_t m_counter;
};