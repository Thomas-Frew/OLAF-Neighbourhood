#pragma once
#include "data_processing.hpp"
#include <atomic>
#include <cstdint>
#include <format>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

class ClientDataHandler {
  private:
    class ClientData;

  public:
    static auto getInstance() -> ClientDataHandler & {
        static ClientDataHandler instance;
        return instance;
    }

    auto update_client_username(std::string_view old_name,
                                std::string_view new_name) -> void;

    auto register_client(std::string public_key) -> void;

  private:
    ClientDataHandler();

    /**
     * Global mutex for maps + client data
     */
    std::mutex m_lock;

    /**
     * Maps fingerprints to client data
     */
    std::unordered_map<std::string_view, ClientData> m_registered_users;

    /**
     * Maps usernames to fingerprints
     */
    std::unordered_map<std::string_view, std::string_view> m_username_map;

    auto client_of_fingerprint(std::string_view fingerprint) -> ClientData &;

    auto client_of_username(std::string_view username) -> ClientData &;

    class ClientData {
      public:
        ClientData(std::string public_key, std::string username)
            : m_public_key(std::move(public_key)),
              m_fingerprint(sha256(this->m_public_key)),
              m_username(std::move(username)) {}

        ClientData(std::string public_key)
            : ClientData(public_key,
                         std::format("unknown_user_{}", m_counter++)) {}

        auto update_username(std::string new_username) -> void {
            this->m_username = std::move(new_username);
        }

        auto public_key() const -> std::string_view {
            return this->m_public_key;
        };
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
};
