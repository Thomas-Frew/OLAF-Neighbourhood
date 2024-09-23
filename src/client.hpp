#pragma once

#include "data_processing.hpp"
#include <cstdint>
#include <string>

class Client {
  public:
    Client(std::string public_key, std::string private_key)
        : m_public_key(public_key), m_private_key(private_key),
          m_identifier(base64_encode(sha256(public_key))), m_counter(0) {}

    std::string getPublicKey();
    std::string getPrivateKey();
    std::string getIdentifier();
    uint32_t getCounter();

    // void run();
    // std::string generateSignature(const std::string &input,
    //                               const uint32_t counter);

  private:
    std::string m_public_key;
    std::string m_private_key;
    std::string m_identifier;
    uint32_t m_counter;
};
