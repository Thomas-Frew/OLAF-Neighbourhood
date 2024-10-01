#pragma once

#include <fstream>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

inline void handle_openssl_error() { ERR_print_errors_fp(stderr); }

inline void handle_encryption_errors() {
    ERR_print_errors_fp(stderr);
    throw std::runtime_error("Error occurred during encryption/decryption.");
}

inline std::string base64_encode(const std::string &input) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    // Create BIO filters for base64 encoding and memory buffer
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // Disable newline when encoding base64 (no line breaks in the output)
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // Write the input data to the BIO and flush it to complete encoding
    BIO_write(bio, input.c_str(), input.size());
    BIO_flush(bio);

    // Retrieve the encoded data from the BIO memory
    BIO_get_mem_ptr(bio, &buffer_ptr);
    BIO_set_close(bio, BIO_NOCLOSE);

    // Create a string from the buffer pointer
    std::string encoded_data(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return encoded_data;
}

inline std::string base64_decode(const std::string &input) {
    BIO *bio, *b64;
    char buffer[input.size()]; // Buffer to hold the decoded data
    int decoded_length;

    // Create BIO filters for base64 decoding and memory buffer
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.c_str(), input.size());
    bio = BIO_push(b64, bio);

    // Disable newline handling
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // Perform the decoding
    decoded_length = BIO_read(bio, buffer, input.size());
    BIO_free_all(bio);

    // Create a string from the buffer with the decoded data
    return std::string(buffer, decoded_length);
}

inline std::string encryptRSA(const std::string &plaintext,
                              const std::string &key) {
    // Create RSA structure from PEM string
    RSA *rsa = nullptr;
    BIO *bio = BIO_new_mem_buf((void *)key.c_str(), -1);
    if (bio == nullptr) {
        throw std::runtime_error("Failed to create BIO.");
    }

    rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (rsa == nullptr) {
        throw std::runtime_error("Failed to read RSA public key.");
    }

    // Encrypt the plaintext
    std::string ciphertext(RSA_size(rsa), '\0');
    int result = RSA_public_encrypt(
        plaintext.size(), (unsigned char *)plaintext.c_str(),
        (unsigned char *)ciphertext.data(), rsa, RSA_PKCS1_OAEP_PADDING);

    RSA_free(rsa);

    // Check for errors during encryption
    if (result == -1) {
        throw std::runtime_error(
            "RSA encryption failed: " +
            std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    // Resize the ciphertext to actual length
    ciphertext.resize(result);
    return base64_encode(ciphertext);
}

inline std::optional<std::string> decryptRSA(const std::string &ciphertext,
                                             const std::string &key) {
    // Decode base64 ciphertext
    std::string decoded_ciphertext = base64_decode(ciphertext);

    // Create RSA structure from PEM string
    RSA *rsa = nullptr;
    BIO *bio = BIO_new_mem_buf((void *)key.c_str(), -1);
    if (bio == nullptr) {
        return std::nullopt;
    }

    rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (rsa == nullptr) {
        return std::nullopt;
    }

    // Decrypt the ciphertext
    std::string plaintext(RSA_size(rsa), '\0');
    int result = RSA_private_decrypt(
        decoded_ciphertext.size(), (unsigned char *)decoded_ciphertext.c_str(),
        (unsigned char *)plaintext.data(), rsa, RSA_PKCS1_OAEP_PADDING);

    RSA_free(rsa);

    // Check for errors during decryption
    if (result == -1) {
        throw std::runtime_error(
            "RSA decryption failed: " +
            std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }

    // Resize the plaintext to actual length
    plaintext.resize(result);
    return plaintext;
}

inline std::string aes_gcm_encrypt(const std::string &plaintext,
                                   const std::string &key) {
    // Generate a random 12-byte IV
    unsigned char iv[12];
    if (!RAND_bytes(iv, sizeof(iv))) {
        throw std::runtime_error("Failed to generate IV");
    }

    // Prepare buffers for ciphertext and tag
    std::vector<unsigned char> ciphertext(plaintext.size());
    unsigned char tag[EVP_GCM_TLS_TAG_LEN];

    // Create the context for encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create context");
    }

    // Initialize encryption
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    // Set IV length
    if (1 !=
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set IV length");
    }

    // Initialize with key and IV
    if (1 != EVP_EncryptInit_ex(
                 ctx, NULL, NULL,
                 reinterpret_cast<const unsigned char *>(key.data()), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set key and IV");
    }

    // Encrypt the plaintext
    int len;
    if (1 != EVP_EncryptUpdate(
                 ctx, ciphertext.data(), &len,
                 reinterpret_cast<const unsigned char *>(plaintext.data()),
                 plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt");
    }

    int ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;

    // Get the authentication tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN,
                                 tag)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get tag");
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Combine IV, ciphertext, and tag into a single string
    std::string encrypted(reinterpret_cast<const char *>(iv), sizeof(iv));
    encrypted.append(reinterpret_cast<const char *>(ciphertext.data()),
                     ciphertext_len);
    encrypted.append(reinterpret_cast<const char *>(tag), EVP_GCM_TLS_TAG_LEN);

    return base64_encode(encrypted); // Assuming base64_encode is defined
}

inline std::string aes_gcm_decrypt(const std::string &encrypted,
                                   const std::string &key) {
    // Decode base64
    std::string decoded =
        base64_decode(encrypted); // Assuming base64_decode is defined

    // Extract the IV, ciphertext, and tag from the decoded data
    unsigned char iv[12];
    std::copy(decoded.begin(), decoded.begin() + 12, iv);

    std::vector<unsigned char> tag(EVP_GCM_TLS_TAG_LEN);
    std::copy(decoded.end() - EVP_GCM_TLS_TAG_LEN, decoded.end(), tag.begin());

    std::vector<unsigned char> ciphertext(decoded.begin() + 12,
                                          decoded.end() - EVP_GCM_TLS_TAG_LEN);

    // Prepare buffer for decrypted plaintext
    std::vector<unsigned char> plaintext(ciphertext.size());

    // Create the context for decryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create context");
    }

    // Initialize decryption
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    // Set IV length
    if (1 !=
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set IV length");
    }

    // Initialize with key and IV
    if (1 != EVP_DecryptInit_ex(
                 ctx, NULL, NULL,
                 reinterpret_cast<const unsigned char *>(key.data()), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set key and IV");
    }

    // Provide the ciphertext and receive the plaintext
    int len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                               ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt");
    }

    // Set the tag for verification
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN,
                                 tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set tag");
    }

    // Finalize decryption
    int plaintext_len = len;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return std::string(reinterpret_cast<const char *>(plaintext.data()),
                           plaintext_len);
    } else {
        throw std::runtime_error(
            "Decryption failed: Authentication tag mismatch");
    }
}

inline std::string sha256(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    // Initialize, update, and finalize the SHA-256 hash computation
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    std::string hash_str{reinterpret_cast<char *>(hash), SHA256_DIGEST_LENGTH};
    return base64_encode(hash_str);
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

    // Read the public key from the BIO (PEM format)
    public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (public_key == nullptr) {
        handle_openssl_error();
        return false;
    }

    // Create a new message digest context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        handle_openssl_error();
        EVP_PKEY_free(public_key);
        return false;
    }

    // Initialize verification operation
    if (1 != EVP_DigestVerifyInit(mdctx, nullptr, md, nullptr, public_key)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(public_key);
        return false;
    }

    // Update the context with the message data
    if (1 != EVP_DigestVerifyUpdate(mdctx, message.data(), message.size())) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(public_key);
        return false;
    }

    // Finalize the verification and compare the signature
    bool result =
        EVP_DigestVerifyFinal(
            mdctx, reinterpret_cast<const unsigned char *>(signature.data()),
            signature.size()) == 1;

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(public_key);

    return result;
}

inline std::string sign_message(const std::string &private_key_pem,
                                const std::string &message) {
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY *private_key = nullptr;

    // Create BIO for private key PEM
    BIO *bio = BIO_new_mem_buf(private_key_pem.data(), -1);
    if (bio == nullptr) {
        handle_openssl_error();
        return "";
    }

    // Read the private key from the BIO
    private_key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (private_key == nullptr) {
        handle_openssl_error();
        return "";
    }

    // Create a new message digest context for signing
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        handle_openssl_error();
        EVP_PKEY_free(private_key);
        return "";
    }

    // Initialize the signing operation with PSS padding
    if (1 != EVP_DigestSignInit(mdctx, nullptr, md, nullptr, private_key)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return "";
    }

    // Set the padding to PSS with a salt length of 32 bytes
    if (1 != EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(mdctx),
                                          RSA_PKCS1_PSS_PADDING)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return "";
    }

    // Set the salt length to 32 bytes
    if (1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_pkey_ctx(mdctx), 32)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return "";
    }

    // Hash the message data
    if (1 != EVP_DigestSignUpdate(mdctx, message.data(), message.size())) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return "";
    }

    // Determine the signature size
    size_t sig_len = 0;
    if (1 != EVP_DigestSignFinal(mdctx, nullptr, &sig_len)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return "";
    }

    // Allocate memory for the signature and finalize signing
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

    // Free the context and private key
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(private_key);

    return base64_encode(signature);
}
