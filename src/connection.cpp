#include "connection.hpp"
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
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
      m_ws(m_ioc, m_ctx), m_state(ConnState::CONNECTED) {
    // Disable old + insecure verisons of TLS/SSL
    this->m_ctx.set_options(ssl::context::default_workarounds |
                            ssl::context::single_dh_use |
                            ssl::context::no_sslv2 | ssl::context::no_sslv3 |
                            ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1);

    // Sign with CA
    this->m_ctx.set_verify_mode(ssl::verify_peer);
    this->m_ctx.set_default_verify_paths();
    this->m_ctx.load_verify_file("cert.pem");

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

    // Set a decorator to change the User-Agent of the handshake
    this->m_ws.set_option(
        websocket::stream_base::decorator([](websocket::request_type &req) {
            req.set(http::field::user_agent,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " websocket-client");
        }));

    // Perform the websocket handshake
    this->m_ws.handshake(host, "/");
};

auto Connection::read() -> std::string {
    // Shared pointers so they don't get destroyed upon returning
    auto buffer = beast::flat_buffer();
    this->m_ws.read(buffer);
    return beast::buffers_to_string(buffer.data());
}

auto Connection::write(std::string_view message) -> void {
    this->m_ws.write(net::buffer(message));
};

auto Connection::close() -> void {
    if (this->m_state == ConnState::SHUTDOWN) {
        throw std::runtime_error("Closing already closed connection");
    }

    std::cerr << "Closing websocket..." << std::endl;
    this->m_ws.close(websocket::close_code::normal);

    std::cerr << "Shutting down connection..." << std::endl;
    this->m_ws.next_layer().shutdown();

    std::cerr << "Gracefully shutdown!" << std::endl;
    this->m_state = ConnState::SHUTDOWN;
}

Connection::~Connection() {
    if (this->m_state != ConnState::SHUTDOWN) {
        this->close();
        std::cerr << "Warning: Connection destroyed without being "
                     "automatically closed. Closed automatically."
                  << std::endl;
    }
}
