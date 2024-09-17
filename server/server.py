import asyncio
import websockets
import json
import ssl
import sys
from enum import Enum
import hashlib
import warnings


class MessageType(Enum):
    # Client-made messages
    HELLO = "hello"
    PUBLIC_CHAT = "public_chat"
    CLIENT_LIST_REQUEST = "client_list_request"

    # Server-made messages
    SERVER_HELLO = "server_connect"
    CLIENT_LIST = "client_list"
    CLIENT_UPDATE_REQUEST = "client_update_request"
    CLIENT_UPDATE = "client_update"


def hash_string_sha256(input_string):
    """ Hashing helper. """
    sha256 = hashlib.sha256()
    sha256.update(input_string.encode('utf-8'))
    return sha256.hexdigest()


class Server:
    def __init__(self, host, port):
        # Suppress specific deprecation warnings for SSL options
        warnings.filterwarnings("ignore", category=DeprecationWarning,
                                message="ssl.OP_NO_TLS*")
        warnings.filterwarnings("ignore", category=DeprecationWarning,
                                message="ssl.OP_NO_SSL*")

        # Server details
        self.host = host
        self.port = port
        self.hostname = f"{host}:{port}"

        self.clients = {}  # Socket -> Client Public Key
        self.servers = {}  # Socket -> Server Hostname

        self.all_clients = {}  # Server hostname -> User List
        self.all_clients[self.hostname] = []

        self.counter = 0

        self.last_message = None

        # Setup SSL context
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.options |= ssl.OP_NO_SSLv2
        self.ssl_context.options |= ssl.OP_NO_SSLv3
        self.ssl_context.options |= ssl.OP_NO_TLSv1
        self.ssl_context.options |= ssl.OP_NO_TLSv1_1
        self.ssl_context.options |= ssl.OP_SINGLE_DH_USE

        # Load certificate chain
        self.ssl_context.load_cert_chain(
            certfile="server.cert", keyfile="server.key")

    def create_message(self, message_type):
        self.counter = self.counter + 1
        signature = "temporary_signature"

        match message_type:
            case MessageType.SERVER_HELLO:
                return {
                    "type": MessageType.SERVER_HELLO.value,
                    "data": {
                        "hostname": self.hostname
                    },
                    "signature": signature,
                    "counter": self.counter
                }

            case MessageType.CLIENT_LIST:
                return {
                    "type": MessageType.CLIENT_LIST.value,
                    "servers": [
                        {
                            "address": address,
                            "clients": client_list
                        } for address, client_list in self.all_clients.items()
                    ]
                }

            case MessageType.CLIENT_UPDATE_REQUEST:
                return {
                    "type": MessageType.CLIENT_UPDATE_REQUEST.value,
                    "data": {
                        "hostname": self.hostname
                    },
                    "signature": signature,
                    "counter": self.counter
                }

            case MessageType.CLIENT_UPDATE:
                return {
                    "type": MessageType.CLIENT_UPDATE.value,
                    "data": {
                        "hostname": self.hostname,
                        "clients": list(self.clients.keys())
                    },
                    "signature": signature,
                    "counter": self.counter
                }

            case _:
                print(f"Cannot create message of type {message_type}")

    async def start_server(self):
        """ Begin the server and its core functions. """

        server_loop = websockets.serve(
            self.handle_first, self.host, self.port, ssl=self.ssl_context)

        # Create listeners
        async with server_loop:
            # Start the server loop
            print(f"Server started on {self.hostname}")
            server_task = asyncio.create_task(self.wait_for_shutdown())

            # Establish neighborhood connections
            await self.connect_to_neighbourhood()

            # Wait until server is manually stopped
            await server_task

    async def wait_for_shutdown(self):
        """ Shutdown waiter to keep the server alive. """

        try:
            await asyncio.Future()  # Run the server until manually stopped

        except asyncio.CancelledError:
            print("Server is shutting down.")

    async def connect_to_neighbourhood(self):
        """ Connect to all servers in the neighbourhood. """

        # Construct messages
        hello_message = self.create_message(MessageType.SERVER_HELLO)
        client_update_request_message = self.create_message(
            MessageType.CLIENT_UPDATE_REQUEST)

        # The auth context of the server you are connecting to
        # TODO: Check if we should use anything non-default
        auth_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        # TODO: Get the cert of the server you want to connect to
        auth_context.load_verify_locations(cafile="server.cert")

        # NOTE: Currently, neighbourhood.olaf is a glorified IP list.
        # This will change. It will include public keys.
        with open('neighbourhood.olaf', 'r') as file:
            # Ensure no leading/trailing whitespace
            hostnames = [line.strip() for line in file]

        # Connect to all servers in the neighbourhood
        server_listeners = []
        for hostname in hostnames:
            # Don't connect to yourself, silly!
            if (hostname == self.hostname):
                continue

            server_listeners.append(self.connect_to_server(
                hostname,
                auth_context,
                hello_message,
                client_update_request_message
            ))
        await asyncio.gather(*server_listeners)
        print("Done connecting to neighbourhood!")

    async def connect_to_server(
        self,
        hostname,
        auth_context,
        hello_message,
        client_update_request_message
    ):
        """ Establish a connection with a remote server """
        try:
            websocket = await websockets.connect(
                f"wss://{hostname}/", ssl=auth_context
            )

            # Connect to the server with a two-way channel
            await websocket.send(
                json.dumps(hello_message)
            )
            self.servers[hostname] = websocket
            self.all_clients[hostname] = []

            # Get the online list of users
            await websocket.send(
                json.dumps(client_update_request_message)
            )

            # Create listener for server
            asyncio.create_task(self.listener(websocket, self.handle_server))

        except Exception:
            print(f"Could not reach server: {hostname}")

    async def handle_first(self, websocket):
        try:
            async for message in websocket:
                message_json = json.loads(message)
                message_type = MessageType(message_json.get('type'))
                message_data = message_json.get('data')

                match message_type:
                    case MessageType.HELLO:
                        await self.handle_hello(websocket, message_data)
                        print("Handled hello. Returning")
                        return
                    case MessageType.SERVER_HELLO:
                        await self.handle_server_hello(websocket, message_data)
                        print("Handled server hello. Returning")
                        return
                    case _:
                        print(f"Unestablished client sent message of type: {
                              message_type}, ignoring")

        except Exception as e:
            print(f"Unestablished connection closed due to error: {e}")

    async def listener(self, websocket, handler):
        """ Handle messages from clients. """

        try:
            async for message in websocket:
                await handler(websocket, message)

        except websockets.exceptions.ConnectionClosedOK:
            # Connection closed gracefully
            print("Connection closed gracefully")

        except websockets.exceptions.ConnectionClosedError as e:
            print(f"Connection closed due to error: {e}")

        except Exception as e:
            print(f"Internal error, closing connection: {e}")

        finally:
            # Ensure client cleanup on disconnect
            await self.handle_client_disconnect(websocket)

    async def handle_client(self, websocket, message):
        # print(f"Message recieved: {message}")  # DEBUG
        message_json = json.loads(message)
        message_type = MessageType(message_json.get('type'))
        message_data = message_json.get('data')

        # Ignore if message was identical to the most recent one
        # (DOS and loop protection)
        if (hash_string_sha256(message) == self.last_message):
            return

        self.last_message = hash_string_sha256(message)

        # Handle message
        match message_type:
            case MessageType.HELLO:
                await self.handle_hello(websocket, message_data)
            case MessageType.PUBLIC_CHAT:
                await self.handle_public_chat(message_json)
            case MessageType.CLIENT_LIST_REQUEST:
                await self.handle_client_list_request(websocket)
            case (MessageType.SERVER_HELLO
                  | MessageType.CLIENT_UPDATE_REQUEST
                  | MessageType.CLIENT_UPDATE):
                print(f"Erroneous message type from client: {message_type}")
            case _:
                print(f"Message type not recognized: {message_type}")

        # Forward message if appropriate
        if message_type == MessageType.PUBLIC_CHAT:
            await self.propagate_message(message)

    async def handle_server(self, websocket, message):
        # print(f"Message recieved: {message}")  # DEBUG
        message_json = json.loads(message)
        message_type = MessageType(message_json.get('type'))
        message_data = message_json.get('data')

        # Ignore if message was identical to the most recent one
        # (DOS and loop protection)
        if (hash_string_sha256(message) == self.last_message):
            return

        # Handle message
        match message_type:
            case MessageType.PUBLIC_CHAT:
                await self.handle_public_chat(message_json)
            case MessageType.CLIENT_UPDATE_REQUEST:
                await self.handle_client_update_request(message_data)
            case MessageType.CLIENT_UPDATE:
                await self.handle_client_update(message_data)
            case (MessageType.HELLO
                  | MessageType.SERVER_HELLO
                  | MessageType.CLIENT_LIST_REQUEST):
                print(f"Erroneous message type from server: {message_type}")
            case _:
                print(f"Message type not recognized: {message_type}")

    async def handle_client_disconnect(self, websocket):
        """ Handle client disconnection. """

        # Find the client by websocket
        pub_key_to_remove = None
        for pub_key, client_socket in self.clients.items():
            if client_socket == websocket:
                pub_key_to_remove = pub_key
                break

        if pub_key_to_remove:
            # Remove the client
            del self.clients[pub_key_to_remove]
            self.all_clients[self.hostname].remove(pub_key_to_remove)

            # Log disconnect event
            print(f"Client disconnected with public key: {pub_key_to_remove}")

            # Notify other servers about the update
            client_update_message = self.create_message(
                MessageType.CLIENT_UPDATE)
            await self.propagate_message(json.dumps(client_update_message))

    async def handle_server_hello(self, websocket, message_data):
        """ Handle SERVER_HELLO messages. """
        hostname = message_data.get('hostname')
        self.servers[hostname] = websocket
        self.all_clients[hostname] = []

        # Set up new listener
        new_listener = asyncio.create_task(
            self.listener(websocket, self.handle_server))

        print(f"Server connected with hostname: {hostname}")

        await new_listener

    async def handle_hello(self, websocket, message_data):
        """ Handle HELLO messages. """

        # TODO: Verify no duplicate HELLO messages
        # Also, cannot send other messages prior to HELLO

        # Register client
        pub_key = message_data.get('public_key')
        self.clients[pub_key] = websocket

        self.all_clients[self.hostname].append(pub_key)

        # Set up new listener
        new_listener = asyncio.create_task(
            self.listener(websocket, self.handle_client))

        client_update_message = self.create_message(MessageType.CLIENT_UPDATE)
        await self.propagate_message(json.dumps(client_update_message))

        # Log join event
        print(f"Client connected with public key: {pub_key}")

        await new_listener

    async def handle_public_chat(self, message):
        """ Handle PUBLIC_CHAT messages. """

        # Send public chat message to all clients
        for _, client_socket in self.clients.items():
            await client_socket.send(json.dumps(message))

    async def handle_client_list_request(self, websocket):
        """ Handle CLIENT_LIST_REQUEST messages (respond with CLIENT_LIST). """

        client_list_message = self.create_message(MessageType.CLIENT_LIST)
        await websocket.send(json.dumps(client_list_message))

    async def handle_client_update_request(self, message_data):
        """ Handle CLIENT_UPDATE_REQUEST messages """
        """ respond with CLIENT_UPDATE """

        connecting_hostname = message_data.get('hostname')
        client_update_message = self.create_message(MessageType.CLIENT_UPDATE)

        await self.servers[connecting_hostname].send(
            json.dumps(client_update_message)
        )

    async def handle_client_update(self, message_data):
        """ Handle CLIENT_UPDATE message. """

        hostname = message_data.get('hostname')
        client_list = message_data.get('clients')

        self.all_clients[hostname] = client_list
        print(f"Updated client list to: {self.all_clients}")

    async def propagate_message(self, message):
        """ Propagate a message to all connected clients of the server. """

        # TODO: Proper error handling

        server_misses = []

        for hostname, server_socket in self.servers.items():
            try:
                await server_socket.send(message)
            except Exception as e:
                print(f"Failed to send message to neighbour {hostname}: {e}")
                server_misses.append(hostname)

        for hostname in server_misses:
            del self.servers[hostname]
            del self.all_clients[hostname]
            print(f"Server disconnected with hostname: {hostname}")


if __name__ == "__main__":
    # Read port from the command line
    port = 1443
    if len(sys.argv) > 1:
        port = int(sys.argv[1])  # Ensure port is an integer

    # Begin and run server
    server = Server("localhost", port)
    asyncio.run(server.start_server())
