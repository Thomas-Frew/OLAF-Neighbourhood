# OLAF-Neighbourhood
An implementation of the OLAF's Neighbourhood protocol.

## Building
CMake should manage all dependencies. In the project root, type the following commands:
```bash
mkdir build
cmake -B build
cmake --build build
```

The client will be built as `build/src/client/client`
The server will be built as `build/src/server/server`

## Server Setup
The server requires a 2048-bit RSA private key, and a certificate. These are stored in `ssl/key.pem` and `ssl/cert.pem` respectively.

You can generate them with the following commands:
```bash
mkdir ssl
openssl genrsa -out ssl/server.key 2048
openssl req -new -key ssl/server.key -out ssl/server.csr
openssl x509 -req -days 30 -in ssl/server.csr -signkey ssl/server.key -out ssl/server.cert
```
