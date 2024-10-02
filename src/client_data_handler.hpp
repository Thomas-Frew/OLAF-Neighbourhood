#pragma once
#include "data_processing.hpp"
#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <utility>

class ClientDataHandler {
  private:
    class ClientData;

  public:
    static auto get_instance() -> ClientDataHandler & {
        static ClientDataHandler instance;
        return instance;
    }

    auto update_client_username(const std::string &old_name,
                                const std::string &new_name) -> void;

    auto is_registered(const std::string &fingerprint) -> bool;

    auto register_client(const std::string &public_key) -> std::string;

    auto set_private_key(std::string key) -> void {
        this->m_private_key = std::move(key);
    }

    auto get_private_key() const -> const std::string & {
        return this->m_private_key;
    };

    auto get_username(const std::string &fingerprint) -> std::string;

    auto get_fingerprint(const std::string &username) -> std::string;

    auto get_pubkey_from_fingerprint(const std::string &fingerprint)
        -> std::string;
    auto get_pubkey_from_username(const std::string &username) -> std::string;

    auto check_counter(const std::string &fingerprint, std::uint64_t counter)
        -> bool;

  private:
    ClientDataHandler() = default;

    std::string m_private_key;

    /**
     * Global mutex for maps + client data
     */
    std::mutex m_lock;

    /**
     * Maps fingerprints to client data
     */
    std::map<std::string, ClientData> m_registered_users;

    /**
     * Maps usernames to fingerprints
     */
    std::map<std::string, std::string> m_username_map;

    /**
     * Get client data from a fingerprint. Assumes we have a lock on the global
     * mutex.
     */
    auto client_of_fingerprint(const std::string &fingerprint) -> ClientData &;

    /**
     * Get client data from a username. Assumes we have a lock on the global
     * mutex.
     */
    auto client_of_username(const std::string &username) -> ClientData &;

    /**
     * Get client data from a fingerprint, in a const context. Assumes we have a
     * lock on the global mutex.
     */
    auto client_of_fingerprint(const std::string &fingerprint) const
        -> const ClientData &;

    /**
     * Get client data from a username, in a const context. Assumes we have a
     * lock on the global mutex.
     */
    auto client_of_username(const std::string &username) const
        -> const ClientData &;

    class ClientData {
      public:
        ClientData(std::string public_key, std::string username)
            : m_public_key(std::move(public_key)),
              m_fingerprint(sha256(this->m_public_key)),
              m_username(std::move(username)), m_counter(0) {}

        ClientData(std::string public_key)
            : ClientData(public_key, "unknown_user_" +
                                         std::to_string(m_username_counter++)) {
        }

        auto update_username(std::string new_username) -> void {
            this->m_username = std::move(new_username);
        }

        auto public_key() const -> const std::string & {
            return this->m_public_key;
        };

        auto fingerprint() const -> const std::string & {
            return this->m_fingerprint;
        };

        auto username() const -> const std::string & {
            return this->m_username;
        };

        auto valid_counter(std::uint64_t counter) -> bool {
            if (counter < this->m_counter) {
                return false;
            } else {
                this->m_counter = counter + 1;
                return true;
            }
        }

      private:
        std::string m_public_key;
        std::string m_fingerprint;

        // Users without a username will be assigned a number
        static std::atomic<std::uint64_t> m_username_counter;
        std::string m_username;
        std::uint64_t m_counter;

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
