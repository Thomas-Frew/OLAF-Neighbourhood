#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <cstdlib>
#include <iostream>
#include <string>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

// Sends a WebSocket message and prints the response
int main(int argc, char **argv) {
    try {
        // Default settings
        std::string host = "localhost";
        std::string port = "1443";

        // Port is customisable
        if (argc == 2) {
            port = argv[1];
        } else if (argc != 1) {
            std::cerr << "Usage: client <port>?\n";
            return EXIT_FAILURE;
        }

        // The io_context is required for all I/O
        net::io_context ioc;

        // These objects perform our I/O
        tcp::resolver resolver{ioc};
        ssl::context ctx{ssl::context::tlsv13_client};
        websocket::stream<ssl::stream<tcp::socket>> ws{ioc, ctx};

        // Set SNI (Server Name Indication) for the SSL handshake,
        // required for many HTTPS servers
        if (!SSL_set_tlsext_host_name(ws.next_layer().native_handle(),
                                      host.c_str())) {
            boost::system::error_code ec{static_cast<int>(::ERR_get_error()),
                                         net::error::get_ssl_category()};
            throw boost::system::system_error{ec};
        }

        // Look up the domain name
        auto const results = resolver.resolve(host, port);

        // Make the connection on the IP address we get from a lookup
        auto ep = net::connect(ws.next_layer().next_layer(), results);

        // Update the host_ string. This will provide the value of the
        // Host HTTP header during the WebSocket handshake.
        // See https://tools.ietf.org/html/rfc7230#section-5.4
        host += ':' + ep.port();

        // Perform ssl handshake
        ws.next_layer().handshake(ssl::stream_base::client);

        // Set a decorator to change the User-Agent of the handshake
        ws.set_option(
            websocket::stream_base::decorator([](websocket::request_type &req) {
                req.set(http::field::user_agent,
                        std::string(BOOST_BEAST_VERSION_STRING) +
                            " websocket-client-coro");
            }));

        // Perform the websocket handshake
        ws.handshake(host, "/");

        std::string input;
        auto prompt = [&input]() {
            std::cout << "[CLIENT]: " << std::flush;
            std::getline(std::cin, input);
        };

        // Send/receive messages from server until client quits
        for (prompt(); input != "/quit"; prompt()) {
            // Send the message
            ws.write(net::buffer(std::string(input)));

            // This buffer will hold the incoming message
            beast::flat_buffer buffer;

            // Read a message into our buffer
            ws.read(buffer);

            // The make_printable() function helps print a ConstBufferSequence
            std::cout << beast::make_printable(buffer.data()) << std::endl;
        }

        // Close the WebSocket connection
        ws.close(websocket::close_code::normal);

        // If we get here then the connection is closed gracefully

    } catch (std::exception const &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
