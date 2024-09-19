#include "client.hpp"
#include <iomanip>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <string>

std::string sha256(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    std::stringstream input_stream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        input_stream << std::hex << std::setw(2) << std::setfill('0')
                     << (int)hash[i];
    }

    return input_stream.str();
}

std::string base64_encode(const std::string &input) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, input.c_str(), input.size());
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &buffer_ptr);
    BIO_set_close(bio, BIO_NOCLOSE);

    std::string encoded_data(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return encoded_data;
}

std::string Client::getPublicKey() { return this->m_public_key; }

uint32_t Client::getCounter() { return this->m_counter++; }

std::string Client::generateSignature(const std::string &input) {
    std::string sha256_input = sha256(input);
    return base64_encode(sha256_input);
}