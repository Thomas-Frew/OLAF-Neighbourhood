# OLAF-Neighbourhood
An implementation of the OLAF's Neighbourhood protocol.

## Client

### Client Setup

In the client directory, the following is required:

- `cert.pem`: The certificate of the server the client is connecting to.
- `private_key.pem`: The private key of the client.
- `public_key.pem`: The public key of the client.

You can generate the client keys with the following commands:

```bash
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

### Building the Client
The Client is written in C++, with all dependencies managed by CMake. To build the client, write the following commands in the project root:
```bash
mkdir build
cmake -B build
cmake --build build
```

The client will be built as `/client/client`.

### Running the Client

The client is run within the `client` directory as `./client [port]?

- `[ip]`: An optional argument containing the port of the server. Defaults to 1443.

### Initialisation Behaviour

When the client is run, the following happens:
1. The client tries to establish a websocket connection with the server.
2. The client sends a `HELLO` message to the server.
3. The client sends a `CLIENT_LIST_REQUEST` message to the server.
4. The set of online clients is displayed in the terminal.
5. The CLI starts up.

### CLI

The client CLI supports the following commands:

- `public_chat`: Send a message to all connected users.
- `online_list`: Request a client list from your connected server.

## Server

### Server Setup

In the server directory, the following is required:

- `cert.pem`: The certificate of the server.
- `private_key.pem`: The private key of the server.
- `public_key.pem`: The public key of the server.

You can generate the client keys with the following commands:

The server requires a 2048-bit RSA private key, public key, and a certificate. These are stored in `private_key.pem`, `public_key.pem` and `cert.pem` respectively.

You can generate them with the following commands:
```bash
openssl genrsa -out private_key.pem 2048
openssl req -new -key private_key.pem -out csr.pem
openssl x509 -req -days 30 -in server.csr -signkey private_key.pem -out cert.pem
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

### Defining the Neighbourhood

The server requires a file containing all hostnames of servers in their neighbourhood (in the form `host:port`). These are stored in `neighbourhood.olaf` as plaintext, followed by the server's public key. Subsequent servers are separated by a newline.

```
localhost:1443
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----

localhost:1444
...
```

### Building the Server
The Client is written in Python and, therefore, does not get built.

All source code is stored in `server`, with the entry point being `server.py`.

### Running the Server

The client is run within the `server` directory as `python3 ./server.py [port]?`. It requires python 3.10 or above.

- `[port]`: An optional argument containing the port of the server. Defaults to 1443.

## Setting up multiple clients/servers
You will likely want to run multiple clients/servers on the same machine for testing. To do this, you should set up a directory (e.g. subdirectories of the `server` and `client` directories) for each instance of a client/server, with its own keys and other required files. Then, simply run the client or server from inside these directories (e.g., call `../client` rather than `./client` from `./client/user1/`)
