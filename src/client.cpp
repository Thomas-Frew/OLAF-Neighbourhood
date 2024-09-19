#include "client.hpp"
#include <string>

std::string Client::getPublicKey() { return this->m_public_key; }

std::string Client::getPrivateKey() { return this->m_private_key; }

uint32_t Client::getCounter() { return this->m_counter++; }