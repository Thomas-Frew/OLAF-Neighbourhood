#include "web_connection.hpp"
#include <curl/curl.h>
#include <iostream>
#include <string>

static size_t WriteCallback(void *contents, size_t size, size_t nmemb,
                            std::string *response) {
    size_t totalSize = size * nmemb;
    response->append((char *)contents, totalSize);
    return totalSize;
}

WebConnection::WebConnection(std::string host, std::string port)
    : file_server_url("https://" + host + ":" + port) {}

auto WebConnection::read_file(std::string filename) -> void {
    CURL *curl;
    CURLcode res;
    FILE *file;

    // Initialize CURL
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL,
                         (file_server_url + "/" + filename).c_str());

        // Skip SSL certificate verification (equivalent to -k in curl)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // Open the file for writing
        file = fopen(filename.c_str(), "wb");
        if (file) {
            // Set the write function to write the response data to the file
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);

            // Perform the request, and check for errors
            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::cerr << "curl_easy_perform() failed: "
                          << curl_easy_strerror(res) << std::endl;
            } else {
                std::cout << "File downloaded successfully!" << std::endl;
            }

            fclose(file);
        } else {
            std::cerr << "Failed to open file for writing: " << filename
                      << std::endl;
        }

        // Cleanup CURL
        curl_easy_cleanup(curl);
    } else {
        std::cerr << "Failed to initialize CURL!" << std::endl;
    }
};

auto WebConnection::write_file(std::string filename) -> void {
    CURL *curl;
    CURLcode res;

    // Initialize CURL
    curl = curl_easy_init();
    if (curl) {
        std::cout << file_server_url + "/api/upload" << '\n';
        curl_easy_setopt(curl, CURLOPT_URL,
                         (file_server_url + "/api/upload").c_str());

        // Skip SSL certificate verification (equivalent to -k in curl)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // Specify that this is a POST request
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        // Set the file to be uploaded as binary data
        FILE *file = fopen(filename.c_str(), "rb");
        if (file) {
            // Capture file data
            curl_easy_setopt(curl, CURLOPT_READDATA, file);

            // Capture file size
            fseek(file, 0L, SEEK_END);
            curl_off_t file_size = ftell(file);
            rewind(file);
            curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, file_size);

            // Perform the request, and check for errors
            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::cerr << "curl_easy_perform() failed: "
                          << curl_easy_strerror(res) << std::endl;
            } else {
                std::cout << "File uploaded successfully!" << std::endl;
            }

            fclose(file);
        } else {
            std::cerr << "Failed to open file: " << filename << std::endl;
        }

        // Cleanup CURL
        curl_easy_cleanup(curl);
    } else {
        std::cerr << "Failed to initialize CURL!" << std::endl;
    }
};
