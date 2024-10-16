# Testing Process

## Test List

### Server: Startup

When a server is lanched, it should:

- [ ] Try to connect to all others in their neighbourhood.
- [ ] Send a "SERVER_HELLO" message to all connected neighbours.
- [ ] Send a "CLIENT_UPDATE_REQUEST" message to all connected neighbours.
- [ ] Log all neighbours that did had a failed connection.

### Server: Runtime

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

When a server is running, it should:

- [ ] Sign all signed messages with RSA, PSS padding with 256-SHA.
- [ ] Reject non-HTTPS and Secure Websocket connections.
- [ ] Only accept connections with certificates from their CA.
- [ ] Reject messages with invalid JSON.
- [ ] Reject signed messages with invalid signatures.
- [ ] Reject messages with invalid counters.
- [ ] Reject file uploads larger than 500 kB.
- [ ] Commit and retrieve files directly from the "tmp" directory.
- [ ] Drop a client or server connection that is behaving strangely.
- [ ] Log all messages in a secure location.

### Client: Startup

When a client is lanched, it should:

- [ ] Try to connect with only its parent server.
- [ ] Send a "HELLO" message to its parent server.
- [ ] Send a "CLIENT_LIST_REQUEST" to its parent server.
- [ ] Display the clients contained in the resulting "CLIENT_LIST" message.
- [ ] Start listening for commands through the terminal.

### Client: Runtime

When a client is running, it should:

- [ ] Avoid crashing randomly.
- [ ] Handle "PUBLIC_CHAT" messages by displaying the sender and message.
- [ ] Handle "PRIVATE_CHAT" messages by attempting to decrypt them, displaying the sender and message if successful.
- [ ] Handle "CLIENT_LIST" messages by attempting to decrypt them, displaying the sender and message if successful.

### Client: Interactivity

- [ ] Send "PUBLIC_CHAT" messages to everyone with the "public_chat" command.
- [ ] Send "PRIVATE_CHAT" messages to everyone with the "private_chat"/"chat" command.
- [ ]Send "CLIENT_LIST_REQUEST" messages to their parent server with the "online_list" command.
- [ ] Upload files to their parent server with the "upload" command.
- [ ] Download files from their parent server with the "download" command.
- [ ] Locally rename either clients with the "rename" command.

### Client: Security

When a server is running, it should:

- [ ] Sign all signed messages with RSA, PSS padding with 256-SHA.
- [ ] Encrypt data in "PRIVATE_CHAT" messages symmetrically with AES GCM, and a securely generated key.
- [ ] Encrypt symm_keys in "PRIVATE_CHAT" messages asymetrically with RSA.
- [ ] Reject non-HTTPS and Secure Websocket connections.
- [ ] Only accept connections with certificates from their CA.
- [ ] Reject messages with invalid JSON.
- [ ] Reject signed messages with invalid signatures.
- [ ] Reject messages with invalid counters.
- [ ] Reject messages from unknown users (not in the client list).
- [ ] Drop a server connection that is behaving strangely.

## Self-Testing

### Atomicity

Only one component of the software (either the client or server), should be updated at a time. Then, one of two tests can be performed. 

### When to Run Tests

If the feature is only partly complete, debug statements can be used to test its functionality. The entire "Test List" does not need to be tested, although it could be useful to test closely coupled features. 

If a feature is complete, an official test should be added to the "Test List" to ensure it works. Then, all tests from the "Test List" should be conducted to prevent regressing behaviour.

All tests from the "Test List" should also be conducted when performing a pull request. If one of the tests fail, this could be mentioned as a comment on the PR.

## Interoperability Testing


### Forms of Interoperability

### Server-Server Tests

### Server-Client Tests

### Client-Client Tests

### Exploit Enumeration