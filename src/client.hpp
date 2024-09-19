#pragma once

#include <cstdint>
#include <string>

class Client {
  public:
    Client(std::string public_key, std::string private_key)
        : m_public_key(public_key), m_private_key(private_key), m_counter(0) {}

    std::string getPublicKey();
    std::string getPrivateKey();
    uint32_t getCounter();

    void run();
    std::string generateSignature(const std::string &input,
                                  const uint32_t counter);

  private:
    std::string m_public_key;
    std::string m_private_key;
    uint32_t m_counter;
};
