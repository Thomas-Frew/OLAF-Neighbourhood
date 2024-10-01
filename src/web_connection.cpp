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

auto WebConnection::read_file(std::string resource) -> void {
    CURL *curl;
    CURLcode result_code;
    FILE *file;
    std::string filename;

    size_t last_slash = resource.find_last_of('/');
    filename = resource.substr(last_slash + 1);

    // Initialize CURL
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, resource.c_str());

        // Skip SSL certificate verification (equivalent to -k in curl)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // Open the file for writing
        file = fopen(filename.c_str(), "wb");
        if (file) {
            // Set the write function to write the response data to the file
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);

            // Perform the request, and check for errors
            result_code = curl_easy_perform(curl);
            if (result_code != CURLE_OK) {
                std::cerr << "curl_easy_perform() failed: "
                          << curl_easy_strerror(result_code) << std::endl;
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

auto WebConnection::write_file(std::string filename) -> std::string {
    CURL *curl;
    CURLcode result_code;
    std::string response;

    // Initialize CURL
    curl = curl_easy_init();
    if (curl) {
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
            // curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            // Capture file size
            fseek(file, 0L, SEEK_END);
            curl_off_t file_size = ftell(file);
            rewind(file);
            curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, file_size);

            // Perform the request, and check for errors
            result_code = curl_easy_perform(curl);
            if (result_code != CURLE_OK) {
                std::cerr << "curl_easy_perform() failed: "
                          << curl_easy_strerror(result_code) << std::endl;
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

    return response;
};
