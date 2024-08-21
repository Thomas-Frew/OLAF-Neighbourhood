cmake_policy(SET CMP0167 NEW)

find_package(OpenSSL REQUIRED)
find_package(Boost 1.83.0 REQUIRED system thread)
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})
