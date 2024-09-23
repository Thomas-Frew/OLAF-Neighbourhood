#pragma once
#include "data_processing.hpp"
#include <atomic>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <utility>

class ClientData {
  public:
    ClientData(const std::string &public_key)
        : m_public_key(public_key), m_fingerprint(sha256(public_key)),
          m_username(std::format("unknown_user_{}", m_counter++)) {}

    ClientData(const std::string &public_key, std::string username)
        : m_public_key(public_key), m_fingerprint(sha256(public_key)),
          m_username(std::move(username)) {}

    auto update_username(std::string new_username) -> void {
        this->m_username = std::move(new_username);
    }

    auto public_key() const -> std::string_view { return this->m_public_key; };
    auto public_key_ref() const -> const std::string & {
        return this->m_public_key;
    };

    auto fingerprint() const -> std::string_view {
        return this->m_fingerprint;
    };
    auto fingerprint_ref() const -> const std::string & {
        return this->m_fingerprint;
    };

    auto username() const -> std::string_view { return this->m_username; };
    auto username_ref() const -> const std::string & {
        return this->m_username;
    };

  private:
    std::string m_public_key;
    std::string m_fingerprint;

    // Users without a username will be assigned a number
    static std::atomic<std::uint64_t> m_counter;
    std::string m_username;

  public:
    // We don't want to be making expensive copies
    ClientData(const ClientData &) = delete;
    ClientData &operator=(const ClientData &) = delete;

    // It's OK to move these around
    ClientData(ClientData &&) noexcept = default;
    ClientData &operator=(ClientData &&) noexcept = default;

    // Rule of 5
    ~ClientData() = default;
};
