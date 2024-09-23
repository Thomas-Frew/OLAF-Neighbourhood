#pragma once
#include "client_data.hpp"
#include <expected>
#include <memory>
#include <string_view>
#include <unordered_map>

class ClientDataHandler {
  public:
    enum class ErrorCode {
        NoSuchUser,
    };

    static auto get_instance() -> ClientDataHandler & {
        static ClientDataHandler instance;
        return instance;
    }

    auto client_of_fingerprint(std::string_view fingerprint) const
        -> std::expected<std::shared_ptr<const ClientData>,
                         ClientDataHandler::ErrorCode>;

    auto client_of_username(std::string_view username) const
        -> std::expected<std::shared_ptr<const ClientData>,
                         ClientDataHandler::ErrorCode>;

    auto update_client_username(std::string_view old_name,
                                std::string_view new_name)
        -> std::expected<void, ErrorCode>;

  private:
    ClientDataHandler() = default;
    /**
     * Maps fingerprints to client data
     */
    std::unordered_map<std::string_view, std::shared_ptr<ClientData>>
        m_registered_users;

    /**
     * Maps usernames to fingerprints
     */
    std::unordered_map<std::string_view, std::string_view> m_username_map;
};
