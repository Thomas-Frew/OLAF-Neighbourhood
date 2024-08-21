#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <iostream>
#include <memory>
#include <string>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

// This function handles an incoming WebSocket connection
class WebSocketSession : public std::enable_shared_from_this<WebSocketSession> {
public:
    WebSocketSession(tcp::socket socket) : ws_(std::move(socket)) {}

    void run() {
        // Set a decorator to change the User-Agent of the handshake
        ws_.set_option(websocket::stream_base::decorator([](websocket::request_type& req) { req.set(http::field::user_agent, std::string(BOOST_BEAST_VERSION_STRING) + " websocket-server"); }));

        // Perform the WebSocket handshake
        ws_.async_accept(beast::bind_front_handler(&WebSocketSession::on_accept, shared_from_this()));
    }

private:
    void append_to_buffer(boost::beast::flat_buffer& buffer, const std::string& data) {
        boost::asio::mutable_buffer mutable_buf = buffer.prepare(data.size());
        std::memcpy(mutable_buf.data(), data.data(), data.size());
        buffer.commit(data.size());
    }

    void on_accept(beast::error_code ec) {
        if (ec) {
            std::cerr << "Accept failed: " << ec.message() << std::endl;
            return;
        }

        // Read a message from the client
        ws_.async_read(buffer_, beast::bind_front_handler(&WebSocketSession::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t) {
        if (ec) {
            std::cerr << "Read failed: " << ec.message() << std::endl;
            return;
        }

        // Construct a response buffer
        boost::beast::flat_buffer response_buffer;
        append_to_buffer(response_buffer, "Thanks for your message: ");
        append_to_buffer(response_buffer, beast::buffers_to_string(buffer_.data()));

        // Echo the message back to the client
        ws_.async_write(response_buffer.data(), beast::bind_front_handler(&WebSocketSession::on_write, shared_from_this()));
    }

    void on_write(beast::error_code ec, std::size_t) {
        if (ec) {
            std::cerr << "Write failed: " << ec.message() << std::endl;
            return;
        }

        // Clear the buffer and close the connection
        buffer_.consume(buffer_.size());
        ws_.async_close(websocket::close_code::normal, beast::bind_front_handler(&WebSocketSession::on_close, shared_from_this()));
    }

    void on_close(beast::error_code ec) {
        if (ec) {
            std::cerr << "Close failed: " << ec.message() << std::endl;
            return;
        }
    }

    websocket::stream<tcp::socket> ws_;
    beast::flat_buffer buffer_;
};

// This function handles the accepting of new connections
class WebSocketServer {
public:
    WebSocketServer(net::io_context& ioc, unsigned short port) : acceptor_(ioc, tcp::endpoint(tcp::v4(), port)) {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept([this](beast::error_code ec, tcp::socket socket) {
            if (!ec) {
                std::make_shared<WebSocketSession>(std::move(socket))->run();
            }
            do_accept();
        });
    }

    tcp::acceptor acceptor_;
};

int main(int argc, char* argv[]) {
    try {
        // Check command-line arguments
        if (argc != 2) {
            std::cerr << "Usage: server <port>\n";
            return EXIT_FAILURE;
        }
        unsigned short port = static_cast<unsigned short>(std::stoi(argv[1]));

        // Create the I/O context
        net::io_context ioc;

        // Create and run the server
        WebSocketServer server(ioc, port);
        ioc.run();
    } catch (std::exception const& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
