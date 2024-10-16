# Testing

![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)


We are proud to present the user/interoperability testing framework we used for our CLI chat app, based on [OLAF-Neighbourhood protocol](https://github.com/xvk-64/2024-secure-programming-protocol).

This document contains our testing suite and approaches for user/iteroperability testing.

## Test List

### Server: Startup
![Static Badge](https://img.shields.io/badge/Tests-Passing-green)

When a server is lanched, it should:

- [ ] Try to connect to all others in their neighbourhood.
- [ ] Send a "SERVER_HELLO" message to all connected neighbours.
- [ ] Send a "CLIENT_UPDATE_REQUEST" message to all connected neighbours.
- [ ] Log all neighbours that had a failed connection.

### Server: Runtime 

![Static Badge](https://img.shields.io/badge/Tests-Passing-green)

When a server is running, it should:

- [ ] Avoid crashing randomly.
- [ ] Handle "HELLO" messages by adding the client to their client list.
- [ ] Handle "SERVER_HELLO" messages by creating an empty client list for the connecting server.
- [ ] Handle "CLIENT_UPDATE_REQUEST" messages by sending their client list to the requesting server.
- [ ] Handle "CLIENT_LIST_REQUEST" messages by sending their client list to the requesting client.
- [ ] Forward "PUBLIC_CHAT" messages to all connected clients and servers.
- [ ] Forward "PRIVATE_CHAT" messages to all connected clients and servers.
- [ ] Handle POST requests to "api/upload" by committing the client's uploaded file.
- [ ] Handle GET requests by retrieving the client's requested file.
- [ ] Log all recieved messages and network events.

### Server: Security

![Static Badge](https://img.shields.io/badge/Tests-Passing-green)

When a server is running, it should:

- [ ] Sign all signed messages with RSA, PSS padding with 256-SHA.
- [ ] Reject non-HTTPS and Websocket over HTTPS connections.
- [ ] Only accept connections with certificates from their CA.
- [ ] Reject messages with invalid JSON.
- [ ] Reject signed messages with invalid signatures.
- [ ] Reject messages with invalid counters.
- [ ] Reject file uploads larger than 500 kB.
- [ ] Commit and retrieve files directly from the "uploads" directory.
- [ ] Log all messages in a secure location.

### Client: Startup

![Static Badge](https://img.shields.io/badge/Tests-Passing-green)

When a client is lanched, it should:

- [ ] Try to connect with only its parent server.
- [ ] Send a "HELLO" message to its parent server.
- [ ] Send a "CLIENT_LIST_REQUEST" to its parent server.
- [ ] Display the clients contained in the resulting "CLIENT_LIST" message.
- [ ] Start listening for commands through the terminal.

### Client: Runtime

![Static Badge](https://img.shields.io/badge/Tests-Passing-green)

When a client is running, it should:

- [ ] Avoid crashing randomly.
- [ ] Handle "PUBLIC_CHAT" messages by displaying the sender and message.
- [ ] Handle "PRIVATE_CHAT" messages by attempting to decrypt them, displaying the sender and message if successful.
- [ ] Handle "CLIENT_LIST" messages by displaying all online users.

### Client: Interactivity

![Static Badge](https://img.shields.io/badge/Tests-Passing-green)

- [ ] Send "PUBLIC_CHAT" messages to everyone with the "public_chat" command.
- [ ] Send "PRIVATE_CHAT" messages to everyone with the "private_chat"/"chat" command.
- [ ] Send "CLIENT_LIST_REQUEST" messages to their parent server with the "online_list" command.
- [ ] Upload files to their parent server with the "upload" command.
- [ ] Download files from their parent server with the "download" command.
- [ ] Locally rename clients with the "rename" command.

### Client: Security

![Static Badge](https://img.shields.io/badge/Tests-Passing-green)

When a server is running, it should:

- [ ] Sign all signed messages with RSA, PSS padding with 256-SHA.
- [ ] Encrypt data in "PRIVATE_CHAT" messages symmetrically with AES GCM, and a securely generated key.
- [ ] Encrypt symm_keys in "PRIVATE_CHAT" messages asymetrically with RSA.
- [ ] Reject non-HTTPS and Websocket over HTTPS connections.
- [ ] Only accept connections with certificates from their CA.
- [ ] Reject messages with invalid JSON.
- [ ] Reject signed messages with invalid signatures.
- [ ] Reject messages with invalid counters.
- [ ] Reject messages from unknown users (not in the client list).

## Self-Testing

We used a rigorous testing framework when developing the app, to produce directed quality assurance and avoid regressing behaviour.

### Atomicity

Only one component of the software (either the client or server), should be updated at a time. Then, one of two tests can be performed. 

### When to Run Tests

If the feature is only partly complete, debug statements can be used to test its functionality. The entire "Test List" does not need to be tested, although it could be useful to test closely coupled features. 

If a feature is complete, an official test should be added to the "Test List" to ensure it works. Then, a copy of the "Test List" should be created, and all tests verified, to prevent regressing behaviour.

Full testing should also be conducted when performing a pull request. If one of the tests fail, this could be mentioned as a comment on the PR.

## Interoperability Testing

To test interoperabiltiy with other groups, we execute all tests from the "Test List". This rule ensures that our interoperability testing remains as rigorous as self-testing.

However, there are several combinations of our/other clients/servers to run these tests with. Which combinations capture the highest degree of interaction?

### Types of Interactions

There are four kinds of interactions we would like to work:

- **SS**: Server-Server interoperability: Our servers can interepret messages created by the other servers, and vice-versa.

- **SC**: Server-Client interoperability: Our servers can interepret messages created by the other clients, and vice-versa.

- **CS**: Client-Server interoperability: Our clients can interepret messages from created by the other servers, and vice-versa.

- **CC**: Client-Client interoperability: Our clients can interepret messages from created by the other clients, and vice-versa. 

### Levels of Interoperability

Some combinations of clients/servers require more kinds of interactions to function. They should be used over  combinations that require fewer kinds of interactions, if possible.

We are arranged these combination into levels, with lower-numbered levels containing a higher degree of interaction (and should be tested first).

![Levels of Interoperability](/assets/levels-of-interoperability.png)