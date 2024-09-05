# OLAF-Neighbourhood
An implementation of the OLAF's Neighbourhood protocol.

## Client

### Building the Client
The Client is written in C++, with all dependencies managed by CMake. To build the client, write the following commands in the project root:
```bash
mkdir build
cmake -B build
cmake --build build
```

The client will be built as `/client/client`.

### Running the Client

The client is run within the `client` directory, as `./client [port]? [pub_key]?`

- `[ip]`: An optional argument containing the port of the server. Defaults to 1443.
- `[pub_key]`: An optional argument containing the public key of the client. Defaults to 'default'.

### Initialisation Behaviour

When the client is run, the following happens:
1. The client tries to establish a websocket connection with the server.
2. The client sends a `HELLO` message to the server.
3. The client sends a `CLIENT_LIST_REQUEST` message to the server.
4. The list of online clients is displayed in the terminal.
5. The CLI starts up.

### CLI 

The client CLI supports the following commands:

- `public_chat`: Send a message to all connected users.
- `online_list`: Request a client list from your connected server.

### Required Files

In the `client` directory, the following is required:

- `server.cert`: The certificate of the server the client is connecting to.


## Server Setup
The server requires a 2048-bit RSA private key, and a certificate. These are stored in `ssl/key.pem` and `ssl/cert.pem` respectively.

You can generate them with the following commands:
```bash
mkdir ssl
openssl genrsa -out ssl/server.key 2048
openssl req -new -key ssl/server.key -out ssl/server.csr
openssl x509 -req -days 30 -in ssl/server.csr -signkey ssl/server.key -out ssl/server.cert
```
