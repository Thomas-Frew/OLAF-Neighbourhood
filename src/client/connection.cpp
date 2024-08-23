#include "connection.hpp"
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <future>
#include <iostream>
#include <string>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

// Create connection
Connection::Connection(std::string host, std::string_view port)
    : m_ioc(), m_ctx(ssl::context::tlsv13_client), m_resolver(m_ioc),
      m_ws(m_ioc, m_ctx), m_graceful_shutdown(false) {
    // Disable old + insecure verisons of TLS/SSL
    this->m_ctx.set_options(ssl::context::default_workarounds |
                            ssl::context::single_dh_use |
                            ssl::context::no_sslv2 | ssl::context::no_sslv3 |
                            ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1);

    // Sign with CA
    this->m_ctx.set_verify_mode(ssl::verify_peer);
    this->m_ctx.set_default_verify_paths();
    this->m_ctx.load_verify_file("ssl/server.cert");

    // Disable compression - can lead to vulnerabilities
    SSL_CTX_set_options(this->m_ctx.native_handle(), SSL_OP_NO_COMPRESSION);

    // Might want to add a SSL_CTX_set_cipher_list...

    // Set SNI (Server Name Indication) for the SSL handshake,
    // required for many HTTPS servers
    if (!SSL_set_tlsext_host_name(this->m_ws.next_layer().native_handle(),
                                  host.c_str())) {
        boost::system::error_code ec{static_cast<int>(::ERR_get_error()),
                                     net::error::get_ssl_category()};
        throw boost::system::system_error{ec};
    }

    // Look up the domain name
    auto const results = this->m_resolver.resolve(host, port);

    // Make the connection on the IP address we get from a lookup
    auto ep = net::connect(this->m_ws.next_layer().next_layer(), results);

    // Update the host_ string. This will provide the value of the
    // Host HTTP header during the WebSocket handshake.
    // See https://tools.ietf.org/html/rfc7230#section-5.4
    host += ':' + ep.port();

    // Perform ssl handshake
    this->m_ws.next_layer().handshake(ssl::stream_base::client);

    // Perform ssl handshake
    this->m_ws.next_layer().handshake(ssl::stream_base::client);

    // Set a decorator to change the User-Agent of the handshake
    this->m_ws.set_option(
        websocket::stream_base::decorator([](websocket::request_type &req) {
            req.set(http::field::user_agent,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " websocket-client");
        }));

    // Perform the websocket handshake
    this->m_ws.handshake(host, "/");

    // Set up IO thread
    this->m_io_worker = std::thread([this]() {
        std::println(std::cerr, "IOC running.");
        this->m_ioc.run();
    });
};

// Read message (blocks on I/O)
auto Connection::read() -> std::future<std::string> {
    // Shared pointers so they don't get destroyed upon returning
    auto promise = std::make_shared<std::promise<std::string>>();
    auto buffer = std::make_shared<beast::flat_buffer>();
    this->m_ws.async_read(
        *buffer, [buffer, promise](beast::error_code ec, std::size_t) {
            if (!ec) {
                promise->set_value(beast::buffers_to_string(buffer->data()));
            } else {
                promise->set_exception(
                    std::make_exception_ptr(std::runtime_error(ec.message())));
            }
        });
    return promise->get_future();
}

// Send message
auto Connection::write(std::string_view message) -> void {
    this->m_ws.write(net::buffer(message));
};

auto Connection::close() -> void

{
    std::println(std::cerr, "Closing connection...");
    this->m_ws.close(websocket::close_code::normal);
    std::println(std::cerr, "Joining ioc worker...");
    this->m_io_worker.join();
    std::println(std::cerr, "Gracefully shutdown!");
    this->m_graceful_shutdown = true;
}
Connection::~Connection() {
    if (this->m_graceful_shutdown == false) {
        this->close();
        std::println(std::cerr, "Warning: Connection destroyed without being "
                                "automatically closed. Closed automatically.");
    }
}
