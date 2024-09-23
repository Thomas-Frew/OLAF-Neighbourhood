#include "client_data_handler.hpp"
#include <string_view>
#include <utility>

auto ClientDataHandler::client_of_fingerprint(
    std::string_view fingerprint) const -> const ClientData & {
    std::unreachable();
}

auto ClientDataHandler::client_of_username(std::string_view username) const
    -> const ClientData & {
    std::unreachable();
}

auto update_client_username(std::string_view old_name,
                            std::string_view new_name) -> void {
    std::unreachable();
}
