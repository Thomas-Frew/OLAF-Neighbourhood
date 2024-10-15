/* Created by Jack Morton and Thomas Frew, of group 48. */

#pragma once
#include <string>

class WebConnection {
  public:
    WebConnection(std::string host, std::string port);

    void read_file(std::string filename);
    std::string write_file(std::string filename);

  private:
    std::string file_server_url;
};
