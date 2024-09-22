#pragma once

#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <sstream>
#include <string>

inline void handle_openssl_error() { ERR_print_errors_fp(stderr); }

inline bool verify_signature(const std::string &public_key_pem,
                             const std::string &message,
                             const std::string &signature) {
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY *public_key = nullptr;
    BIO *bio = BIO_new_mem_buf(public_key_pem.data(), -1);
    if (bio == nullptr) {
        handle_openssl_error();
        return false;
    }

    public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (public_key == nullptr) {
        handle_openssl_error();
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        handle_openssl_error();
        EVP_PKEY_free(public_key);
        return false;
    }

    if (1 != EVP_DigestVerifyInit(mdctx, nullptr, md, nullptr, public_key)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(public_key);
        return false;
    }

    if (1 != EVP_DigestVerifyUpdate(mdctx, message.data(), message.size())) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(public_key);
        return false;
    }

    bool result =
        EVP_DigestVerifyFinal(
            mdctx, reinterpret_cast<const unsigned char *>(signature.data()),
            signature.size()) == 1;

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(public_key);

    return result;
}

inline std::string sha256(const std::string &input) {
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

inline std::string base64_encode(const std::string &input) {
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

inline std::string sign_message(const std::string &private_key_pem,
                                const std::string &message) {
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY *private_key = nullptr;
    BIO *bio = BIO_new_mem_buf(private_key_pem.data(), -1);
    if (bio == nullptr) {
        handle_openssl_error();
        return "";
    }

    private_key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (private_key == nullptr) {
        handle_openssl_error();
        return "";
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        handle_openssl_error();
        EVP_PKEY_free(private_key);
        return "";
    }

    if (1 != EVP_DigestSignInit(mdctx, nullptr, md, nullptr, private_key)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return "";
    }

    if (1 != EVP_DigestSignUpdate(mdctx, message.data(), message.size())) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return "";
    }

    size_t sig_len = 0;
    if (1 != EVP_DigestSignFinal(mdctx, nullptr, &sig_len)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return "";
    }

    std::string signature(sig_len, '\0');
    if (1 != EVP_DigestSignFinal(
                 mdctx, reinterpret_cast<unsigned char *>(&signature[0]),
                 &sig_len)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return "";
    }

    signature.resize(sig_len);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(private_key);

    return base64_encode(signature);
}

inline std::string load_key(const std::string &filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    std::ostringstream oss;
    oss << file.rdbuf();
    return oss.str();
}