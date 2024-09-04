import asyncio
import websockets
import json
import ssl
import sys 

from enum import Enum

class MessageType(Enum):
    HELLO = 0
    PUBLIC_CHAT = 1
    
class Server:
    def __init__(self):
        # Public key -> Client socket
        self.clients = {}
        
        # Setup SSL context
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.options |= ssl.OP_NO_SSLv2
        self.ssl_context.options |= ssl.OP_NO_SSLv3
        self.ssl_context.options |= ssl.OP_NO_TLSv1
        self.ssl_context.options |= ssl.OP_NO_TLSv1_1
        self.ssl_context.options |= ssl.OP_SINGLE_DH_USE

        # Load certificate chain
        self.ssl_context.load_cert_chain(certfile="python_server/server.cert", keyfile="python_server/server.key")
        
    def start_server(self, port):
        server_loop = websockets.serve(self.handle_client, "localhost", port, ssl=self.ssl_context)
        
        asyncio.get_event_loop().run_until_complete(server_loop)
        asyncio.get_event_loop().run_forever()
    
    async def handle_client(self, websocket, path):
        try:
            async for message in websocket:
                message_json = json.loads(message)
                message_type = int(message_json.get('message_type'))
                message_data = message_json.get('data')
                
                if message_type == MessageType.HELLO:
                    await self.handle_hello(websocket, message_data)
                    
                if message_type == MessageType.PUBLIC_CHAT:
                    await self.handle_public_chat(websocket, message_data)
                    
                else:
                    print("Message type not recognised")
                
        finally:
            # Always clean up and notify others of the disconnection
            if websocket in self.clients:
                disconnected_pub_key = self.clients.pop(websocket)
                # TODO: Notify clients and servers

    async def handle_hello(self, websocket, message_data):   
        # Register client              
        pub_key = message_data.get('public_key')
        self.clients[websocket] = pub_key
        
        # Log join event
        print(f"Client connected with public key: {pub_key}")
        
    async def handle_public_chat(self, websocket, message_data):
        # Extract public key and message
        pub_key = message_data.get('public_key')
        message = message_data.get('message')
        
        for client in self.clients:
            await client.send(f"From {pub_key}: {message}")

if __name__ == "__main__":
    # Read port from the command line
    port = 1443
    if (len(sys.argv) > 1):
        port = sys.argv[1]
        
    # Begin and run server
    server = Server()
    server.start_server(port)