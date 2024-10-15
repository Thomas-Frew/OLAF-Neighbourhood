/* Created by Jack Morton and Thomas Frew, of group 48. */

#include "client.hpp"
#include <string>

std::string &Client::getPublicKey() { return this->m_public_key; }

std::string &Client::getPrivateKey() { return this->m_private_key; }

std::string &Client::getIdentifier() { return this->m_identifier; }

uint64_t Client::getCounter() { return this->m_counter++; }
