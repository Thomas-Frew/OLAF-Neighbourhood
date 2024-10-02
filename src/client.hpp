#pragma once

#include "data_processing.hpp"
#include <cstdint>
#include <string>

class Client {
  public:
    Client(std::string public_key, std::string private_key)
        : m_public_key(public_key), m_private_key(private_key),
          m_identifier(sha256(public_key)), m_counter(0) {}

    std::string &getPublicKey();
    std::string &getPrivateKey();
    std::string &getIdentifier();
    uint64_t getCounter();

  private:
    std::string m_public_key;
    std::string m_private_key;
    std::string m_identifier;
    uint64_t m_counter;
};
