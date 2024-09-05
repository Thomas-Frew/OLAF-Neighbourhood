import asyncio
import websockets
import json
import ssl
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import secrets
import random

random.seed(secrets.randbits(128))

async def connect(message_type, uri):
    # Generate RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # SSL context setup
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations(cafile="server.cert")

    # Message
    message = None

    hello_message = {
        "type": "hello",
        "data": {
            "public_key": public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        },
        "counter": 1,
        "signature": "Temp"
    }

    public_chat_message = {
        "type": "public_chat",
        "data": {
            "public_key": public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
            "message": "Test message"
        },
        "counter": 1,
        "signature": "Temp"
    }
        
    while True:
        try:
            async with websockets.connect(uri, ssl=ssl_context) as websocket:
                # Send the message
                await websocket.send(json.dumps(hello_message))
                await websocket.send(json.dumps(public_chat_message))

                # Keep the connection alive and listen for incoming messages
                async for message in websocket:
                    print(f"Received message: {message}")

        except (websockets.ConnectionClosedError, websockets.InvalidMessage) as e:
            print(f"Connection error: {e}")
            # Handle reconnection or other recovery logic here
            await asyncio.sleep(1)  # Wait before trying to reconnect
            
if __name__ == "__main__":
    
    # Read message type from the command lien
    message_type = sys.argv[1]
    
    # Read port from the command line
    port = 2763
    if (len(sys.argv) > 2):
        port = sys.argv[2]
        
    uri = "wss://localhost:" + str(port)
    
    asyncio.run(connect(message_type, uri))
