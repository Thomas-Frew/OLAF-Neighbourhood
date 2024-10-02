#include "client_data_handler.hpp"
#include <utility>

std::atomic<std::uint64_t> ClientDataHandler::ClientData::m_username_counter =
    0;

auto ClientDataHandler::update_client_username(
    const std::string &old_name, const std::string &new_name) -> void {
    std::lock_guard guard{this->m_lock};
    if (this->m_username_map.contains(new_name)) {
        throw std::runtime_error{"Username already exists"};
    }
    auto &client = this->client_of_username(old_name);
    // Must be careful updating underlying data
    this->m_username_map.erase(client.username());
    client.update_username(std::string{new_name});
    this->m_username_map.emplace(client.username(), client.fingerprint());
}

auto ClientDataHandler::is_registered(const std::string &fingerprint) -> bool {
    std::lock_guard guard{this->m_lock};
    return this->m_registered_users.contains(fingerprint);
}

auto ClientDataHandler::register_client(const std::string &public_key)
    -> std::string {
    std::lock_guard guard{this->m_lock};
    auto client = ClientData{public_key};

    auto err_check = [](bool inserted) -> void {
        if (!inserted) {
            throw std::runtime_error{"User already registered"};
        }
    };

    auto [_k1, insert_check] =
        this->m_username_map.emplace(client.username(), client.fingerprint());
    err_check(insert_check);

    auto username = client.username();

    auto [_k2, insert_check_2] = this->m_registered_users.emplace(
        client.fingerprint(), std::move(client));
    err_check(insert_check_2);

    return username;
}

auto ClientDataHandler::check_counter(const std::string &fingerprint,
                                      std::uint64_t counter) -> bool {
    std::lock_guard guard{this->m_lock};
    auto &client = this->client_of_fingerprint(fingerprint);
    return client.valid_counter(counter);
}

auto ClientDataHandler::get_username(const std::string &fingerprint)
    -> std::string {
    std::lock_guard guard{this->m_lock};
    return std::string{this->client_of_fingerprint(fingerprint).username()};
}

auto ClientDataHandler::get_fingerprint(const std::string &username)
    -> std::string {
    std::lock_guard guard{this->m_lock};
    return this->client_of_username(username).fingerprint();
}

auto ClientDataHandler::get_pubkey_from_fingerprint(
    const std::string &fingerprint) -> std::string {
    std::lock_guard guard{this->m_lock};
    return this->client_of_fingerprint(fingerprint).public_key();
}
auto ClientDataHandler::get_pubkey_from_username(const std::string &username)
    -> std::string {
    std::lock_guard guard{this->m_lock};
    return this->client_of_username(username).public_key();
}

auto ClientDataHandler::client_of_username(const std::string &username)
    -> ClientData & {

    auto it = this->m_username_map.find(username);
    if (it == this->m_username_map.end()) {
        throw std::runtime_error{"No known user"};
    }

    return client_of_fingerprint(it->second);
}

auto ClientDataHandler::client_of_fingerprint(const std::string &fingerprint)
    -> ClientData & {

    auto it = this->m_registered_users.find(fingerprint);
    if (it == this->m_registered_users.end()) {
        throw std::runtime_error{"No known user"};
    }

    return it->second;
}

auto ClientDataHandler::client_of_fingerprint(
    const std::string &fingerprint) const -> const ClientData & {

    auto it = this->m_registered_users.find(fingerprint);
    if (it == this->m_registered_users.end()) {
        throw std::runtime_error{"No known user"};
    }

    return it->second;
}
