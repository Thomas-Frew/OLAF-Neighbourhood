#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <future>
#include <string>
#include <thread>

class Connection {
  public:
    Connection(std::string host, std::string_view port);

    ~Connection();

    Connection(Connection &) = delete;
    Connection(Connection &&) = delete;
    Connection operator=(Connection &) = delete;
    Connection operator=(Connection &&) = delete;

    std::future<std::string> read();
    void write(std::string_view message);
    void close();

  private:
    boost::asio::io_context m_ioc;
    boost::asio::ssl::context m_ctx;
    boost::asio::ip::tcp::resolver m_resolver;
    boost::beast::websocket::stream<
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>
        m_ws;

    bool m_graceful_shutdown;
    std::thread m_io_worker;
};
