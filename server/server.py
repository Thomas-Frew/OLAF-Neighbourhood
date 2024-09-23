import asyncio
import websockets
import json
import ssl
import sys
from enum import Enum
import warnings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class DataProcessing():
    def verify_signature(public_key, message, signature):
        message = message.encode()
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Verify error: {e}")
            return False

    def sign_message(private_key, message):
        message = message.encode()
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        return signature

    def sha256(input_string):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(input_string.encode('utf-8'))
        return sha256_hash.hexdigest()

    def base64_encode(input_bytes):
        return base64.b64encode(input_bytes).decode('utf-8')

    def base64_decode(input_string):
        return base64.b64decode(input_string)


class MessageType(Enum):
    # Client-made messages
    HELLO = "hello"
    PUBLIC_CHAT = "public_chat"
    PRIVATE_CHAT = "chat"
    CLIENT_LIST_REQUEST = "client_list_request"

    # Server-made messages
    SERVER_HELLO = "server_connect"
    CLIENT_LIST = "client_list"
    CLIENT_UPDATE_REQUEST = "client_update_request"
    CLIENT_UPDATE = "client_update"


class ServerData:
    def __init__(self, websocket, hostname):
        self.websocket = websocket
        self.hostname = hostname


class ClientData:
    def __init__(self, websocket, public_key):
        self.websocket = websocket
        self.public_key = public_key
        self.id = DataProcessing.base64_encode(
            DataProcessing.sha256(public_key).encode())


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

        self.clients = {}  # Client Public Key -> Socket
        self.servers = {}  # Server Hostname -> Socket
        self.socket_identifier = {}  # WebSocket -> Identifier

        self.all_clients = {}  # Server hostname -> User id List
        self.all_clients[self.hostname] = []

        self.counter = 0

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

        # Load private key
        with open("server.key", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend())

        # Load public key
        with open("server.pkey", "rb") as key_file:
            self.public_key = serialization.load_pem_public_key(
                key_file.read(), backend=default_backend())

        # Message types where a client's message must be signed
        self.client_signed = [MessageType.HELLO,
                              MessageType.PUBLIC_CHAT, MessageType.PRIVATE_CHAT]

        # Messge type where a server's message must be signed
        self.server_signed = [MessageType.SERVER_HELLO,
                              MessageType.CLIENT_UPDATE_REQUEST, MessageType.CLIENT_UPDATE]

    def create_message(self, message_type):
        self.counter = self.counter + 1

        match message_type:
            case MessageType.SERVER_HELLO:
                message_data = {"hostname": self.hostname}
                data_string = json.dumps(message_data, separators=(
                    # TODO: Standardise in the protocol
                    ',', ':')) + str(self.counter)

                signature = DataProcessing.sign_message(
                    self.private_key, data_string)
                base64_signature = DataProcessing.base64_encode(signature)

                return {
                    "type": MessageType.SERVER_HELLO.value,
                    "data": message_data,
                    "signature": base64_signature,
                    "counter": self.counter
                }

            case MessageType.CLIENT_LIST:
                return {
                    "type": MessageType.CLIENT_LIST.value,
                    "servers": [
                        {
                            "address": address,
                            "clients": client_list,
                        } for address, client_list in self.all_clients.items()
                    ]
                }

            case MessageType.CLIENT_UPDATE_REQUEST:
                message_data = {"hostname": self.hostname}
                data_string = json.dumps(message_data, separators=(
                    # TODO: Standardise in the protocol
                    ',', ':')) + str(self.counter)

                signature = DataProcessing.sign_message(
                    self.private_key, data_string)
                base64_signature = DataProcessing.base64_encode(signature)

                return {
                    "type": MessageType.CLIENT_UPDATE_REQUEST.value,
                    "data": message_data,
                    "signature": base64_signature,
                    "counter": self.counter
                }

            case MessageType.CLIENT_UPDATE:
                message_data = {"hostname": self.hostname,
                                "clients": list(self.clients.keys())}
                data_string = json.dumps(message_data, separators=(
                    # TODO: Standardise in the protocol
                    ',', ':')) + str(self.counter)

                signature = DataProcessing.sign_message(
                    self.private_key, data_string)
                base64_signature = DataProcessing.base64_encode(signature)

                return {
                    "type": MessageType.CLIENT_UPDATE.value,
                    "data": message_data,
                    "signature": base64_signature,
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

            server_listeners.append(
                self.connect_to_server(hostname, auth_context))
        await asyncio.gather(*server_listeners)
        print("Done connecting to neighbourhood!")

    async def connect_to_server(self, hostname, auth_context):
        """ Establish a connection with a remote server """

        # Construct messages
        hello_message = self.create_message(MessageType.SERVER_HELLO)
        client_update_request_message = self.create_message(
            MessageType.CLIENT_UPDATE_REQUEST)

        try:
            websocket = await websockets.connect(
                f"wss://{hostname}/", ssl=auth_context
            )

            self.servers[hostname] = ServerData(websocket, hostname)
            self.all_clients[hostname] = []
            self.socket_identifier[websocket] = hostname

            # Connect to the server with a two-way channel
            await websocket.send(
                json.dumps(hello_message)
            )

            # Get the online list of users
            await websocket.send(
                json.dumps(client_update_request_message)
            )

            # Create listener for server
            asyncio.create_task(self.listener(
                websocket, self.handle_server, self.handle_server_disconnect
            ))

        except Exception as e:
            print(f"Could not reach server: {hostname} {e}")

    def read_message(self, message):
        # Decode message
        message_json = json.loads(message)
        message_type = MessageType(message_json.get('type'))
        message_data = message_json.get('data')

        return message_json, message_type, message_data

    async def handle_first(self, websocket):
        """ handle the first message sent by a new connection """
        try:
            message = await websocket.recv()
            message_json, message_type, message_data = self.read_message(
                message)

            match message_type:
                case MessageType.HELLO:
                    await self.handle_hello(websocket, message_data)
                case MessageType.SERVER_HELLO:
                    await self.handle_server_hello(websocket, message_data)
                case _:
                    print(f"Unestablished client sent message of type: {
                          message_type}, closing connection")

        except Exception as e:
            print(f"Unestablished connection closed due to error: {e}")

    async def handle_server_hello(self, websocket, message_data):
        """ Handle SERVER_HELLO messages. """
        hostname = message_data.get('hostname')
        self.servers[hostname] = ServerData(websocket, hostname)
        self.all_clients[hostname] = []
        self.socket_identifier[websocket] = hostname

        # Set up new listener
        new_listener = asyncio.create_task(self.listener(
            websocket, self.handle_server, self.handle_server_disconnect
        ))

        print(f"Server connected with hostname: {hostname}")

        await new_listener

    async def handle_hello(self, websocket, message_data):
        """ Handle HELLO messages. """

        # TODO: Verify no duplicate HELLO messages
        # A`ls`o, cannot send other messages prior to HELLO

        # Register client
        public_key = message_data.get('public_key')
        client_data = ClientData(websocket, public_key)

        self.clients[client_data.id] = client_data
        self.socket_identifier[websocket] = client_data.id
        self.all_clients[self.hostname].append(client_data.id)

        # Set up new listener
        new_listener = asyncio.create_task(self.listener(
            websocket, self.handle_client, self.handle_client_disconnect
        ))

        client_update_message = self.create_message(MessageType.CLIENT_UPDATE)
        await self.propagate_message_to_servers(client_update_message)

        # Log join event
        print(f"Client connected with identifier: {client_data.id}")

        await new_listener

    async def listener(self, websocket, handler, disconnect_handler):
        """ Handle incoming messages. """

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
            # Ensure cleanup on disconnect
            print(f"Disconnecting {self.socket_identifier[websocket]}")
            await disconnect_handler(websocket)

    async def handle_client_disconnect(self, websocket):
        """ Handle client disconnection. """

        # Find the client by websocket
        client_id = self.socket_identifier[websocket]
        del self.socket_identifier[websocket]

        # Remove the client
        del self.clients[client_id]
        self.all_clients[self.hostname].remove(client_id)

        # Log disconnect event
        print(f"Client disconnected with id: {client_id}")

        # Notify other servers about the update
        client_update_message = self.create_message(
            MessageType.CLIENT_UPDATE
        )
        await self.propagate_message_to_servers(client_update_message)

    async def handle_server_disconnect(self, websocket):
        """ Handle server disconnection. """

        # Find the server by websocket
        hostname = self.socket_identifier[websocket]
        del self.socket_identifier[websocket]

        # Remove the server
        del self.servers[hostname]
        del self.all_clients[hostname]

        # Log disconnect event
        print(f"Server disconnected with hostname: {hostname}")

    def verify_message(self, public_key, message_json, message_data):
        data_string = json.dumps(message_data, separators=(
            # TODO: Standardise in the protocol
            ',', ':')) + str(message_json.get('counter'))

        base64_signature = message_json.get('signature')
        signature = DataProcessing.base64_decode(base64_signature)

        verify_result = DataProcessing.verify_signature(
            public_key, data_string, signature)

        if (not verify_result):
            print(f"Warning! Signature could not be verified for message.")

    async def handle_server(self, websocket, message):
        message_json, message_type, message_data = self.read_message(message)

        # Verify signature for servers
        if (message_type in self.server_signed):
            self.verify_message(self.public_key, message_json, message_data)

        print(f"Recieved message from server of type {message_type}")

        # Handle message
        match message_type:
            case MessageType.PUBLIC_CHAT:
                await self.handle_public_chat_server(message_json)
            case MessageType.CLIENT_UPDATE_REQUEST:
                await self.handle_client_update_request(message_data)
            case MessageType.CLIENT_UPDATE:
                await self.handle_client_update(message_data)
            case MessageType.PRIVATE_CHAT:
                await self.handle_private_chat_server(message, message_data)
            case (MessageType.HELLO
                  | MessageType.SERVER_HELLO
                  | MessageType.CLIENT_LIST_REQUEST):
                print(f"Erroneous message type from server: {message_type}")
            case _:
                print(f"Message type not recognized: {message_type}")

    async def handle_public_chat_server(self, message):
        """ Handle PUBLIC_CHAT messages from servers. """

        await self.propagate_message_to_clients(message)

    async def handle_client_update_request(self, message_data):
        """
        Handle CLIENT_UPDATE_REQUEST messages (respond with CLIENT_UPDATE).
        """

        hostname = message_data.get('hostname')
        client_update_message = self.create_message(MessageType.CLIENT_UPDATE)

        await self.servers[hostname].websocket.send(
            json.dumps(client_update_message)
        )

    async def handle_client_update(self, message_data):
        """ Handle CLIENT_UPDATE message. """

        hostname = message_data.get('hostname')
        client_list = message_data.get('clients')

        self.all_clients[hostname] = client_list
        print(f"Updated client list to: {self.all_clients}")

    async def handle_private_chat_server(self, message, message_data):
        """ Handle PRIVATE_CHAT message sent from another server """

        await self.propagate_message_to_clients(message)

    async def handle_client(self, websocket, message):
        message_json, message_type, message_data = self.read_message(message)

        # Verify signatures for clients
        if (message_type in self.client_signed):
            client_public_key = None
            for client in self.clients.values():
                if websocket == client.websocket:
                    client_public_key = serialization.load_pem_public_key(
                        client.public_key.encode(),
                        backend=default_backend()
                    )

            self.verify_message(client_public_key, message_json, message_data)

        # Handle message
        match message_type:
            case MessageType.PUBLIC_CHAT:
                await self.handle_public_chat_client(message_json)
            case MessageType.CLIENT_LIST_REQUEST:
                await self.handle_client_list_request(websocket)
            case MessageType.PRIVATE_CHAT:
                await self.handle_private_chat_client(message, message_data)
            case (MessageType.HELLO
                  | MessageType.SERVER_HELLO
                  | MessageType.CLIENT_UPDATE_REQUEST
                  | MessageType.CLIENT_UPDATE):
                print(f"Erroneous message type from client: {message_type}")
            case _:
                print(f"Message type not recognized: {message_type}")

    async def handle_public_chat_client(self, message):
        """ Handle PUBLIC_CHAT messages from clients. """

        await self.propagate_message_to_servers(message)
        await self.propagate_message_to_clients(message)

    async def handle_client_list_request(self, websocket):
        """ Handle CLIENT_LIST_REQUEST messages (respond with CLIENT_LIST). """

        client_list_message = self.create_message(MessageType.CLIENT_LIST)
        await websocket.send(json.dumps(client_list_message))

    async def handle_private_chat_client(self, message, message_data):
        """ Handle PRIVATE_CHAT message from client. """

        destination_servers = message_data.get('destination_servers')

        # Ensure message is valid
        if (len(destination_servers) != len(set(destination_servers))):
            print("Invalid private chat - duplicate servers in list. Ignoring")
            return

        # Propagate message to servers in the destination server list
        for hostname in destination_servers:
            if hostname == self.hostname:
                continue
            server_data = self.servers[hostname]
            if server_data is not None:
                await server_data.websocket.send(message)
            else:
                print(f"Could not send message to unknown server {hostname}")

        await self.propagate_message_to_clients(message)

    async def propagate_message_to_servers(self, message):
        """ Propagate a message to all servers in the neighbourhood. """

        for server_data in self.servers.values():
            print(f"Propagating message to {server_data.hostname}")
            try:
                match message:
                    case str(s):
                        await server_data.websocket.send(s)
                    case _:
                        await server_data.websocket.send(json.dumps(message))
            except Exception as e:
                print(f"Failed to propagate to {server_data.hostname}: {e}")

    async def propagate_message_to_clients(self, message):
        """ Propagate a message to all connected clients of the server. """

        for client_data in self.clients.values():
            print(f"Propagating message to client {client_data.id}")
            try:
                match message:
                    case str(s):
                        await client_data.websocket.send(s)
                    case _:
                        await client_data.websocket.send(json.dumps(message))
            except Exception as e:
                print(f"Failed to propagate to {client_data.id}: {e}")


if __name__ == "__main__":
    # Read port from the command line
    port = 1443
    if len(sys.argv) > 1:
        port = int(sys.argv[1])  # Ensure port is an integer

    # Begin and run server
    server = Server("localhost", port)
    asyncio.run(server.start_server())
