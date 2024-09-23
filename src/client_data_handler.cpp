#include "client_data_handler.hpp"
#include <expected>
#include <string_view>

auto ClientDataHandler::client_of_fingerprint(std::string_view fingerprint)
    const -> std::expected<std::shared_ptr<const ClientData>,
                           ClientDataHandler::ErrorCode> {
    return std::unexpected{ClientDataHandler::ErrorCode::NoSuchUser};
}

auto ClientDataHandler::client_of_username(std::string_view username) const
    -> std::expected<std::shared_ptr<const ClientData>,
                     ClientDataHandler::ErrorCode> {
    return std::unexpected{ClientDataHandler::ErrorCode::NoSuchUser};
}

auto update_client_username(std::string_view old_name,
                            std::string_view new_name)
    -> std::expected<void, ClientDataHandler::ErrorCode> {
    return std::unexpected{ClientDataHandler::ErrorCode::NoSuchUser};
}
