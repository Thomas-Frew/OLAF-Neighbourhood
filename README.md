# OLAF-Neighbourhood Chat App

![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

We are proud to present our CLI chat app, with a backend based on [OLAF-Neighbourhood protocol](https://github.com/xvk-64/2024-secure-programming-protocol). This software is 100% protcol-client and complete with all features, including:

- Listing all members (currently online) in the chat system.
- Private messages to a single participant.
- Group messages to all participants. 
- Point-to-point file transfer.

> Note! While we have implemented all security features of OLAF-Neighbourhood, this submission contains several backdoors intended for exploitation during a CTF. Do not use this in a production setting!

## Server

Servers route messages between clients and other servers, keeping the chat app running.

### Server Setup

In the server directory, the following is required:

- `cert.pem`: The certificate of the server. This is verified by the same root CA as all other servers in the neighbourhood.
- `private_key.pem`: The (2048-bit RSA) private key of the server.
- `public_key.pem`: The (2048-bit RSA) public key of the server.
- `neighbourhood.olaf`: A file containing the public keys of all servers in the neighbourhood.

#### Generating the Root Certificate

A root CA is required to sign all certificates in the neighbourhood. To generate the root certificate, navigate to `/server` and run the following commands:

```bash
openssl genrsa -out rootCA_key.pem 2048
openssl req -x509 -new -nodes -days 30 -key rootCA_key.pem -out rootCA_cert.pem
```

#### Generating the Server Files

Each server has its own RSA key pair and certificate. To generate these, navigate to `/server` and run the following commands:

```bash
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
openssl req -new -key private_key.pem -out csr.pem -subj "/CN=<ip>"
openssl x509 -req -days 30 -in csr.pem -CA rootCA_cert.pem -CAkey rootCA_key.pem -CAcreateserial -out cert.pem
```

### Defining the Neighbourhood

The server requires a file containing all hostnames of servers in their neighbourhood (in the form `host:port`). These are stored in `neighbourhood.olaf` as plaintext, followed by the server's public key. Subsequent servers are separated by an empty line, including at the end of the file.

```
localhost:1443
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----

localhost:1444
...
```

While this file can be constructed manually, it is easier to use commands. Navigate to `/server` place all self-signed server certificates in a directory called `certs`, and then run `c_rehash certs`.

### Building the Server

The Client is written in Python and, therefore, does not get built. All server source code is stored in `server`, with the entry point being `server.py`.

### Running the Server

The server is run in `/server` as `python3 ./server.py [ws_port]? [web_port]?`. Python 3.10 or above is required.

- `[ws_port]`: An optional argument containing the port of the server's websocket service. Defaults to 1443.
- `[web_port]`: An optional argument containing the port of the server's file upload (HTTPS) service. Defaults to 2443.

> Note: In our implementation, [ws_port] and [web_port] must not the be the same.

## Client

Clients connect to servers and use them to message other clients and get information about the network.

### Client Setup

In the client directory, the following is required:

- `rootCA_cert.pem`: The certificate of the root CA used by the neighbourhood of the server the client is connecting to.
- `private_key.pem`: The (2048-bit RSA) private key of the client.
- `public_key.pem`: The (2048-bit RSA) public key of the client.

#### Generating the Client Keys

Each client has its own RSA key pair. To generate these, navigate to `/client`, and run the following commands:

```bash
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

### Building the Client

The Client is written in C++, with all dependencies managed by CMake. To build the client, write the following commands in the project root (`/`):

```bash
mkdir build
cmake -B build
cmake --build build
```

The client will be built as `/client/client`.

### Running the Client

The client is run in `/client` as `./client [host]? [ws_port]? [web_port]?

- `[host]`: An optional argument containing the ip of the server. Defaults to localhost.
- `[ws_port]`: An optional argument containing the port of the server's websocket service. Defaults to 1443.
- `[web_port]`: An optional argument containing the port of the server's file upload (HTTPS) service. Defaults to 2443.

### CLI

The CLI chat app acts like a terminal, forever taking in commands and returning output to `stdout`. It supports the following commands:

- `public_chat [message]`: Send a message to everyone in the neighbourhood.
- `online_list`: List all online users in the neighbourhood.
- `chat [N] [user1@hostname1] ... [userN@hostnameN]`: Send a private message to N users.
- `rename [old_username] [new_username]`: Change a user's alias, making them easier to identify.
- `upload [file_path]`: Upload a local file to the server. File uploads have a limit of 500kB.
- `download https://[hostname]/[filename]`: Download a file from a server.

## Setting up multiple clients/servers

You will likely want to run multiple clients/servers on the same machine for testing. To do this, you should set up a directory (e.g. subdirectories of the `server` and `client` directories) for each instance of a client/server, with its own keys and other required files. Then, simply run the client or server from inside these directories (e.g., call `../client` rather than `./client` from `./client/user1/`)
