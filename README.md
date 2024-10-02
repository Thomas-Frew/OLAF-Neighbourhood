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

The server requires a file containing all hostnames of servers in their neighbourhood (in the form `host:port`). These are stored in `neighbourhood.olaf` as plaintext, followed by the server's public key. Subsequent servers are separated by an empty line.

```
localhost:1443
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----

localhost:1444
...
```

This file should be constructed manually and will be the same between all servers.

### Building the Server

The server is written in Python and, therefore, does not get built. All server source code is stored in `server`, with the entry point being `server.py`.

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

## Exection Examples

### Scenario 1: Client Talks to Self

Let's establish that our certificates are in order.

1. Set up one server, localhost:1443, with the correct certificates and keys.
2. Set up one client with the correct certificates and keys.
3. Run the server with `python3 server.py`.
4. Run the client with `./client`.
5. In the CLI, execute `online_list` and confirm that there is only 1 user.
6. In the CLI, execute `public_chat Hello!` and confirm that you receive this message.

### Scenario 2: Two Clients on the Same Server

Let's check that clients can communicate on the same server.

1. Set up one server, localhost:1443, with the correct certificates and keys.
2. Set up two clients with the correct certificates and keys.
3. Run the server with `python3 server.py`.
4. Run the two clients with `./client`, from their respective directories.
5. In each CLI, execute `online_list` and confirm that there are two users on localhost:1443.
6. In each CLI, execute `public_chat Hello!` and confirm that both clients receive the message.
7. In each CLI, execute `private_chat 1 [other_user]@localhost:1443 Private Hello!`, where [other_user] is the username of the other user. Confirm that ONLY the other user receives this message.

### Scenario 3: Two Clients on Different Servers

Let's check that clients can communicate on different servers.

1. Set up two servers with the correct certificates and keys:
    - localhost:1443
    - localhost:1444
2. Set up two clients with the correct certificates and keys.
3. Run the servers from their respective directories with:
    - `python3 server.py`
    - `python3 server.py 1444 2444` 
4. Run the two clients from their respective directories with:
    - `./client`
    - `./client localhost 1444 2444`
5. In each CLI, execute `online_list` and confirm that there are two users on different_servers servers.
6. In each CLI, execute `public_chat Hello!` and confirm that both clients receive the message.
7. In each CLI, execute `private_chat 1 [other_user]@[other_server] Private Hello!`, where [other_user] is the username of the other user and [other_server] is the server hostname of the other user. Confirm that ONLY the other user receives this message.

### Scenario 4: File Upload

Let's check that file uploads work correctly.

1. Set up one server, localhost:1443, with the correct certificates and keys.
2. Set up one client with the correct certificates and keys.
3. Run the server with `python3 server.py`.
4. Run the client with `./client`.
5. In the CLI, execute `upload [local_filename]`, where [local_filename] is any file on your machine (under 500kB).
6. Note the [remote_filename] the server returns upon a successful upload.
7. In the CLI, execute `download https://localhost:2443/[remote_filename]`.
8. Confirm that the file gets downloaded and is correct.

### Scenario 5: Username Database

Let's check that we can change the aliases of users correctly.

1. Set up one server, localhost:1443, with the correct certificates and keys.
2. Set up two clients with the correct certificates and keys.
3. Run the server with `python3 server.py`.
4. Run the two clients with `./client`, from their respective directories.
5. In each CLI, execute `online_list` and confirm that there are two users on localhost:1443.
6. In one CLI, execute `rename [other_user] alice`, to give the [other_user] the alias of "alice".
7. Then, execute `private_chat 1 alice@localhost:1443 Hello Alice!`. Confirm that ONLY the other user receives this message.
8. In the other CLI, execute `rename [other_user] bob`, to give the [other_user] the alias of "bob".
9. Then, execute `private_chat 1 bob@localhost:1443 Hello Bob!`. Confirm that ONLY the other user receives this message.