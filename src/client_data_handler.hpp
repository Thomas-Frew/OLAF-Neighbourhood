#pragma once
#include "client_data.hpp"
#include <string_view>
#include <unordered_map>

class ClientDataHandler {
  public:
    static auto getInstance() -> ClientDataHandler & {
        static ClientDataHandler instance;
        return instance;
    }

    auto client_of_fingerprint(std::string_view fingerprint) const
        -> const ClientData &;

    auto
    client_of_username(std::string_view username) const -> const ClientData &;

    auto update_client_username(std::string_view old_name,
                                std::string_view new_name) -> void;

  private:
    ClientDataHandler();
    /**
     * Maps fingerprints to client data
     */
    std::unordered_map<std::string_view, ClientData> m_registered_users;

    /**
     * Maps usernames to fingerprints
     */
    std::unordered_map<std::string_view, std::string_view> m_username_map;
};
