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
import os
import re
import uuid
from time import time
from aiohttp import web


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

    def create_base64_signature(private_key, message_data, counter):
        data_string = json.dumps(
            message_data, separators=(',', ':')) + str(counter)
        signature = DataProcessing.sign_message(private_key, data_string)
        base64_signature = DataProcessing.base64_encode(signature)
        return base64_signature

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
    def __init__(self, hostname, public_key):
        self.websocket_hostname = hostname
        self.id = hostname
        self.public_key = public_key
        self.websocket = None
        self.counter = -1

    def add_websocket(self, websocket):
        self.websocket = websocket

    def update_counter(self, counter):
        self.counter = counter


class ClientData:
    def __init__(self, websocket, public_key):
        self.websocket = websocket
        self.public_key = public_key
        self.id = DataProcessing.base64_encode(
            DataProcessing.sha256(public_key).encode())
        self.counter = -1

    def update_counter(self, counter):
        self.counter = counter


class Server:
    def __init__(self, host, websocket_port, file_server_port):
        # Suppress specific deprecation warnings for SSL options
        warnings.filterwarnings("ignore", category=DeprecationWarning,
                                message="ssl.OP_NO_TLS*")
        warnings.filterwarnings("ignore", category=DeprecationWarning,
                                message="ssl.OP_NO_SSL*")

        # Server details
        self.host = host
        self.websocket_port = websocket_port
        self.websocket_hostname = f"{host}:{websocket_port}"
        self.file_server_port = file_server_port
        self.file_server_hostname = f"{host}:{file_server_port}"

        self.clients = {}  # Client Fingerprint -> Client Data
        self.servers = {}  # Server Hostname -> Server Data
        self.socket_identifier = {}  # WebSocket -> Identifier

        self.all_clients = {}  # Server Hostname -> User ID List
        self.all_clients[self.websocket_hostname] = []

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
            certfile="cert.pem", keyfile="private_key.pem")

        # Load private key
        with open("private_key.pem", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend())

        # Load public key
        with open("public_key.pem", "rb") as key_file:
            self.public_key = serialization.load_pem_public_key(
                key_file.read(), backend=default_backend())

        # Message types where a client's message must be signed
        self.client_signed = [MessageType.PUBLIC_CHAT,
                              MessageType.PRIVATE_CHAT]

        # Messge type where a server's message must be signed
        self.server_signed = [MessageType.SERVER_HELLO]

        # File server
        self.file_server = web.Application()
        self.file_server.router.add_post(
            '/api/upload', self.handle_file_upload)
        self.file_server.router.add_get(
            '/{file_name}', self.handle_file_retrieval)

    def create_message(self, message_type):
        self.counter = self.counter + 1

        match message_type:
            case MessageType.SERVER_HELLO:
                message_data = {"hostname": self.websocket_hostname}
                base64_signature = DataProcessing.create_base64_signature(
                    self.private_key, message_data, self.counter)

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
                return {
                    "type": MessageType.CLIENT_UPDATE_REQUEST.value,
                }

            case MessageType.CLIENT_UPDATE:
                return {
                    "type": MessageType.CLIENT_UPDATE.value,
                    "hostname": self.websocket_hostname,
                    "clients": [client.public_key for client in self.clients.values()]
                }

            case _:
                print(f"Cannot create message of type {message_type}")

    async def handle_file_upload(self, request):
        """ Recieve a binary file from the user and store it. """
        file_data = await request.read()

        # Limit files to 1 MB
        string_size =  sys.getsizeof(re.sub(rb'\n+$', b'', file_data))       
        size_in_mb = string_size / (1024*1024)

        if (size_in_mb > 1):
            return web.Response(text="File size cannot exceed 10 MB.\n", status=413)

        file_name = "file_" + str(int(time())) + "_" + str(uuid.uuid4().hex)
        file_path = os.path.join("uploads", file_name)

        with open(file_path, 'wb') as f:
            f.write(file_data)

        file_url = f"{request.host}/{file_name}"

        return web.json_response({'file_url': file_url})

    async def handle_file_retrieval(self, request):
        """ Return a stored file to the user. """
        file_name = request.match_info['file_name']
        file_name = file_name.replace('\\', '/')
        
        # Get absolute path of the file'
        uploads_dir = "uploads"
        file_path = os.path.abspath(os.path.join(uploads_dir, file_name))
        
        # Ensure the file_path is within the uploads directory
        if not os.path.exists(file_path):
            return web.Response(text="The requested file does not exist.\n", status=404)

        if not file_path.startswith(uploads_dir):
            return web.Response(text="Access denied.\n", status=403)

        return web.FileResponse(file_path)

    async def start_server(self):
        """ Begin the server and its core functions. """

        server_loop = websockets.serve(
            self.handle_first, self.host, self.websocket_port, ssl=self.ssl_context)

        # Create listeners
        async with server_loop:
            # Start the server loop
            print(f"Server started on {self.websocket_hostname}")
            server_task = asyncio.create_task(self.wait_for_shutdown())

            # Establish neighborhood connections
            await self.connect_to_neighbourhood()

            # Start file server
            runner = web.AppRunner(self.file_server)
            await runner.setup()
            site = web.TCPSite(
                runner, host=self.host, port=self.file_server_port, ssl_context=self.ssl_context)
            await site.start()

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
        auth_context.load_verify_locations(cafile="rootCA_cert.pem")

        # NOTE: Currently, neighbourhood.olaf is a glorified IP list.
        # This will change. It will include public keys.
        with open('neighbourhood.olaf', 'r') as file:
            hosts = []
            lines = [line.strip() for line in file]
            curr_host = ''
            curr_key = ''

            for line in lines:
                if line == '':
                    hosts.append((curr_host, curr_key))
                    curr_host = ''
                    curr_key = ''
                elif curr_host == '':
                    curr_host = line
                else:
                    curr_key += f'{line}\n'

            if curr_host != '':
                hosts.append((curr_host, curr_key))

        # Connect to all servers in the neighbourhood
        server_listeners = []
        for hostname, public_key_pem in hosts:
            # Don't connect to yourself, silly!
            if (hostname == self.websocket_hostname):
                continue

            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            self.servers[hostname] = ServerData(hostname, public_key)

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

            self.servers[hostname].add_websocket(websocket)
            server_data = self.servers[hostname]
            self.socket_identifier[websocket] = server_data
            self.all_clients[hostname] = []

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

        except Exception:
            print(f"Could not reach server: {hostname}")

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
            _, message_type, message_data = self.read_message(message)

            match message_type:
                case MessageType.HELLO:
                    await self.handle_hello(websocket, message_data)
                case MessageType.SERVER_HELLO:
                    await self.handle_server_hello(websocket, message_data)
                case _:
                    print("Unestablished client sent message of type: " +
                          f"{message_type}, closing connection")

        except Exception as e:
            print(f"Unestablished connection closed due to error: {e}")

    async def handle_server_hello(self, websocket, message_data):
        """ Handle SERVER_HELLO messages. """

        # TODO: Verify server hello
        hostname = message_data.get('hostname')
        self.servers[hostname].add_websocket(websocket)
        self.socket_identifier[websocket] = self.servers[hostname]
        self.all_clients[hostname] = []

        # Set up new listener
        new_listener = asyncio.create_task(self.listener(
            websocket, self.handle_server, self.handle_server_disconnect
        ))

        print(f"Server connected with hostname: {hostname}")

        await new_listener

    async def handle_hello(self, websocket, message_data):
        """ Handle HELLO messages. """

        # TODO: Verify no duplicate HELLO messages
        # Also, cannot send other messages prior to HELLO

        # Register client
        public_key = message_data.get('public_key')
        client_data = ClientData(websocket, public_key)
        self.clients[client_data.id] = client_data
        self.socket_identifier[websocket] = client_data
        self.all_clients[self.websocket_hostname].append(
            client_data.public_key)

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
            print(f"Disconnecting {self.socket_identifier[websocket].id}")
            await disconnect_handler(websocket)

    async def handle_client_disconnect(self, websocket):
        """ Handle client disconnection. """

        # Find the client by websocket
        client_data = self.socket_identifier[websocket]
        del self.socket_identifier[websocket]

        # Remove the client
        del self.clients[client_data.id]
        self.all_clients[self.websocket_hostname].remove(
            client_data.public_key)

        # Log disconnect event
        print(f"Client disconnected with id: {client_data.id}")

        # Notify other servers about the update
        client_update_message = self.create_message(
            MessageType.CLIENT_UPDATE
        )
        await self.propagate_message_to_servers(client_update_message)

    async def handle_server_disconnect(self, websocket):
        """ Handle server disconnection. """

        # Find the server by websocket
        hostname = self.socket_identifier[websocket].id
        del self.socket_identifier[websocket]
        del self.all_clients[hostname]

        self.servers[hostname].websocket = None

        # Log disconnect event
        print(f"Server disconnected with hostname: {hostname}")

    def verify_message(self, public_key, message_json, message_data, user_data):
        counter = int(message_json.get('counter'))

        if user_data.counter >= counter:
            print("Warning! Counter for this message has not been incremeneted.")
        user_data.update_counter(counter)

        data_string = json.dumps(message_data, separators=(
            ',', ':')) + str(counter)

        base64_signature = message_json.get('signature')
        signature = DataProcessing.base64_decode(base64_signature)

        verify_result = DataProcessing.verify_signature(
            public_key, data_string, signature)

        if (not verify_result):
            print("Warning! Signature could not be verified for message.")

    async def handle_server(self, websocket, message):
        message_json, message_type, message_data = self.read_message(message)

        # Handle message
        match message_type:
            case MessageType.PUBLIC_CHAT:
                await self.handle_public_chat_server(message_json)
            case MessageType.CLIENT_UPDATE_REQUEST:
                await self.handle_client_update_request(websocket)
            case MessageType.CLIENT_UPDATE:
                await self.handle_client_update(message_json)
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

    async def handle_client_update_request(self, websocket):
        """
        Handle CLIENT_UPDATE_REQUEST messages (respond with CLIENT_UPDATE).
        """

        client_update_message = self.create_message(MessageType.CLIENT_UPDATE)

        await websocket.send(json.dumps(client_update_message))

    async def handle_client_update(self, message):
        """ Handle CLIENT_UPDATE message. """

        hostname = message.get('hostname')
        client_list = message.get('clients')

        self.all_clients[hostname] = client_list

    async def handle_private_chat_server(self, message, message_data):
        """ Handle PRIVATE_CHAT message sent from another server """

        await self.propagate_message_to_clients(message)

    async def handle_client(self, websocket, message):
        message_json, message_type, message_data = self.read_message(message)

        # Verify signatures for clients
        if (message_type in self.client_signed):
            client_public_key = serialization.load_pem_public_key(
                self.socket_identifier[websocket].public_key.encode(),
                backend=default_backend()
            )

            self.verify_message(
                client_public_key,
                message_json,
                message_data,
                self.socket_identifier[websocket]
            )

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

        destination_servers = set(message_data.get('destination_servers'))

        # Propagate message to servers in the destination server list
        for hostname in destination_servers:
            if hostname == self.websocket_hostname:
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
            if server_data.websocket is None:
                continue
            try:
                match message:
                    case str(s):
                        await server_data.websocket.send(s)
                    case _:
                        await server_data.websocket.send(json.dumps(message))
            except Exception as e:
                print("Failed to propagate to" +
                      f"{server_data.websocket_hostname}: {e}")

    async def propagate_message_to_clients(self, message):
        """ Propagate a message to all connected clients of the server. """

        for client_data in self.clients.values():
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
    websocket_port = 1443
    file_server_port = 2443

    # Read optional websocket port
    if len(sys.argv) > 1:
        websocket_port = int(sys.argv[1])

    if len(sys.argv) > 2:
        file_server_port = int(sys.argv[2])

    # Begin and run server
    server = Server("localhost", websocket_port, file_server_port)
    asyncio.run(server.start_server())
