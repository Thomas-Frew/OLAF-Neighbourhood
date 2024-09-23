#include "client_data_handler.hpp"
#include <string_view>
#include <utility>

std::atomic<std::uint64_t> ClientDataHandler::ClientData::m_counter = 0;

auto ClientDataHandler::update_client_username(
    std::string_view old_name, std::string_view new_name) -> void {
    std::lock_guard guard(this->m_lock);
    if (this->m_username_map.contains(new_name)) {
        throw "Username already exists";
    }
    auto &client = this->client_of_username(old_name);
    // Must be careful updating underlying data
    this->m_username_map.erase(client.username());
    client.update_username(std::string{new_name});
    this->m_username_map.emplace(client.username(), client.fingerprint());
}

auto ClientDataHandler::register_client(std::string public_key) -> void {
    std::lock_guard guard(this->m_lock);
    auto client = ClientData{public_key};

    auto err_check = [](bool inserted) -> void {
        if (!inserted) {
            throw "User already registered";
        }
    };

    auto [_k1, insert_check] = this->m_username_map.emplace(
        std::piecewise_construct, client.username(), client.fingerprint());
    err_check(insert_check);

    auto [_k2, insert_check_2] = this->m_registered_users.emplace(
        std::piecewise_construct, client.fingerprint(), client);
    err_check(insert_check_2);
}

auto ClientDataHandler::get_username(std::string_view fingerprint) const
    -> std::string {
    return std::string{this->client_of_fingerprint(fingerprint).username()};
}

auto ClientDataHandler::get_fingerprint(std::string_view username) const
    -> std::string_view {
    return this->client_of_username(username).fingerprint();
}

auto ClientDataHandler::get_pubkey_from_fingerprint(
    std::string_view fingerprint) const -> std::string_view {
    return this->client_of_fingerprint(fingerprint).public_key();
}
auto ClientDataHandler::get_pubkey_from_username(
    std::string_view username) const -> std::string_view {
    return this->client_of_username(username).public_key();
}

auto ClientDataHandler::client_of_username(std::string_view username)
    -> ClientData & {

    auto it = this->m_username_map.find(username);
    if (it == this->m_username_map.end()) {
        throw "No known user";
    }

    return client_of_fingerprint(it->second);
}

auto ClientDataHandler::client_of_username(std::string_view username) const
    -> const ClientData & {

    auto it = this->m_username_map.find(username);
    if (it == this->m_username_map.end()) {
        throw "No known user";
    }

    return client_of_fingerprint(it->second);
}

auto ClientDataHandler::client_of_fingerprint(std::string_view fingerprint)
    -> ClientData & {

    auto it = this->m_registered_users.find(fingerprint);
    if (it == this->m_registered_users.end()) {
        throw "No known user";
    }

    return it->second;
}

auto ClientDataHandler::client_of_fingerprint(
    std::string_view fingerprint) const -> const ClientData & {

    auto it = this->m_registered_users.find(fingerprint);
    if (it == this->m_registered_users.end()) {
        throw "No known user";
    }

    return it->second;
}
