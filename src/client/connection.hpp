#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <string>

class Connection {
  public:
    Connection(std::string host, std::string_view port);

    ~Connection();

    Connection(Connection &) = delete;
    Connection(Connection &&) = delete;
    Connection operator=(Connection &) = delete;
    Connection operator=(Connection &&) = delete;

    std::string read();
    void write(std::string_view message);
    void close();

  private:
    boost::asio::io_context m_ioc;
    boost::asio::ssl::context m_ctx;
    boost::asio::ip::tcp::resolver m_resolver;
    boost::beast::websocket::stream<
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>
        m_ws;

    enum class ConnState : uint8_t { CONNECTED, SHUTDOWN };
    ConnState m_state;
};
