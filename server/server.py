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
    SERVER_CONNECT = "server_connect"
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
                                message="ssl.OP_NO_TLS* options are deprecated"
                                )
        warnings.filterwarnings("ignore", category=DeprecationWarning,
                                message="ssl.OP_NO_SSL* options are deprecated"
                                )

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

        if (message_type == MessageType.SERVER_CONNECT):
            message = {
                "type": MessageType.SERVER_CONNECT.value,
                "data": {
                    "hostname": self.hostname
                },
                "signature": signature,
                "counter": self.counter
            }
            return message

        elif (message_type == MessageType.CLIENT_LIST):
            message = {
                "type": MessageType.CLIENT_LIST.value,
                "data": {
                    "servers": self.all_clients
                },
                "signature": signature,
                "counter": self.counter
            }
            return message

        elif (message_type == MessageType.CLIENT_UPDATE_REQUEST):
            message = {
                "type": MessageType.CLIENT_UPDATE_REQUEST.value,
                "data": {
                    "hostname": self.hostname
                },
                "signature": signature,
                "counter": self.counter
            }
            return message

        elif (message_type == MessageType.CLIENT_UPDATE):
            message = {
                "type": MessageType.CLIENT_UPDATE.value,
                "data": {
                    "hostname": self.hostname,
                    "clients": list(self.clients.keys())
                },
                "signature": signature,
                "counter": self.counter
            }
            return message

    async def start_server(self):
        """ Begin the server and its core functions. """

        server_loop = websockets.serve(
            self.handle_client, self.host, self.port, ssl=self.ssl_context)

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

        # Consturct messages
        connect_message = self.create_message(MessageType.SERVER_CONNECT)
        client_update_request_message = self.create_message(
            MessageType.CLIENT_UPDATE_REQUEST)

        # The auth context of the server you are connecting to
        # TODO: Get the cert of the server you want to connect to
        auth_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        auth_context.load_verify_locations(cafile="server.cert")

        # Iterate through servers in the list
        with open('neighbourhood.olaf', 'r') as file:
            for connecting_hostname in file:
                # Ensure no leading/trailing whitespace
                connecting_hostname = connecting_hostname.strip()

                # Don't connect to yourself, silly!
                if (connecting_hostname == self.hostname):
                    continue

                try:
                    connecting_websocket = await websockets.connect(
                        f"wss://{connecting_hostname}", ssl=auth_context
                    )

                    # Connect to the server with a two-way channel
                    await connecting_websocket.send(
                        json.dumps(connect_message)
                    )
                    self.servers[connecting_hostname] = connecting_websocket
                    self.all_clients[connecting_hostname] = []

                    # Get the online list of users
                    await connecting_websocket.send(
                        json.dumps(client_update_request_message)
                    )

                except Exception:
                    print(f"Could not reach server: {connecting_hostname}")

    async def handle_client(self, websocket, path):
        """ Handle all messages. """

        try:
            async for message in websocket:
                print(f"Message recieved: {message}")
                message_json = json.loads(message)
                message_type = MessageType(message_json.get('type'))
                message_data = message_json.get('data')

                # Ignore if message was identical to the most recent one
                # (DOS and loop protection)
                if (hash_string_sha256(message) != self.last_message):
                    self.last_message = hash_string_sha256(message)

                    # Handle message
                    if message_type == MessageType.SERVER_CONNECT:
                        await self.handle_server_connect(message_data)

                    elif message_type == MessageType.HELLO:
                        await self.handle_hello(websocket, message_data)

                    elif message_type == MessageType.PUBLIC_CHAT:
                        await self.handle_public_chat(message_json)

                    elif message_type == MessageType.CLIENT_LIST_REQUEST:
                        await self.handle_client_list_request(websocket)

                    elif message_type == MessageType.CLIENT_UPDATE_REQUEST:
                        await self.handle_client_update_request(message_data)

                    elif message_type == MessageType.CLIENT_UPDATE:
                        await self.handle_client_update(message_data)

                    else:
                        print("Message type not recognized")

                    # Forward message if appropriate
                    if message_type == MessageType.PUBLIC_CHAT:
                        await self.propagate_message(message)

        except Exception:
            await self.handle_client_disconnect(websocket)

        finally:
            # Ensure client cleanup on disconnect
            await self.handle_client_disconnect(websocket)

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

    async def handle_server_connect(self, message_data):
        """ Handle SERVER_CONNECT messages. """

        # Don't connect to yourself, silly!
        connecting_hostname = message_data.get('hostname')
        if (connecting_hostname == self.hostname):
            return

        try:
            auth_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            auth_context.load_verify_locations(
                cafile="server.cert")

            connecting_socket = await websockets.connect(
                f"wss://{connecting_hostname}", ssl=auth_context
            )
            self.servers[connecting_hostname] = connecting_socket
            self.all_clients[connecting_hostname] = []

            print(f"Server connected with hostname: {connecting_hostname}")

        except Exception:
            print(f"Failed to send message to neighbor: {connecting_hostname}")

    async def handle_hello(self, websocket, message_data):
        """ Handle HELLO messages. """

        # Register client
        pub_key = message_data.get('public_key')
        self.clients[pub_key] = websocket

        self.all_clients[self.hostname].append(pub_key)

        client_update_message = self.create_message(MessageType.CLIENT_UPDATE)
        await self.propagate_message(json.dumps(client_update_message))

        # Log join event
        print(f"Client connected with public key: {pub_key}")

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
        """ Propogate a message to all connected clients of the server. """

        server_misses = []

        for hostname, server_socket in self.servers.items():
            try:
                await server_socket.send(message)
            except Exception:
                print(f"Failed to send message to neighbor: {hostname}")
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
