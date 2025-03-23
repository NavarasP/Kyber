import paho.mqtt.client as mqtt
from kyber import Kyber512
import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time

# Flags for connection status
Connected = False
Verified = False
Requested = False
Diffie_Hellman = None

# MQTT Configuration
MQTT_BROKER = "localhost"

MQTT_TOPIC_AVAILABLE = "status/Available/Device1"
MQTT_TOPIC_CONNECTED = "status/Connected"
MQTT_TOPIC_CHALLENGE_REQUEST = "challenge/request"
MQTT_TOPIC_CHALLENGE_CHALLENGE = "challenge/challenge"
MQTT_TOPIC_CHALLENGE_RESPONSE = "challenge/response"
MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY = "diffie_hellman/senderkey"
MQTT_TOPIC_DIFFIE_HELLMAN_RECEIVER_KEY = "diffie_hellman/receiverkey"
MQTT_TOPIC_DATA_SEND = "data/send"
MQTT_TOPIC_ACKNOWLEDGMENT = "message/Acknowledged"




# Diffie-Hellman setup
private_key_sender = 6
prime = 23
generator = 5
A = pow(generator, private_key_sender, prime)

# Kyber key pair generation
PUF = os.urandom(32)
sender_pkey, sender_skey = Kyber512._cpapke_keygen(PUF)

print("Private key (sender):", private_key_sender)
print("Generated A:", A)

def on_message(client, userdata, msg):
    global Connected, Diffie_Hellman, Requested, Verified

    print(f"Received: Topic={msg.topic}, Payload={msg.payload.decode()}")

    if msg.topic == MQTT_TOPIC_CONNECTED:
        print("Connected to receiver.")
        Connected = True

    elif msg.topic == MQTT_TOPIC_DIFFIE_HELLMAN_RECEIVER_KEY:
        B = int(msg.payload.decode())
        print(f"Received B value: {B}")
        Diffie_Hellman = pow(B, private_key_sender, prime)
        print(f"Computed shared Diffie-Hellman key: {Diffie_Hellman}")
        client.publish(MQTT_TOPIC_ACKNOWLEDGMENT, "B Received")

    elif msg.topic == MQTT_TOPIC_CHALLENGE_REQUEST:
        Requested = True
        challenge = msg.payload.decode()
        print(f"Challenge received: {challenge}")

        if challenge == "CHALLENGE_ME":
            message = b"abbreviationunquestionablexyz".ljust(32)
            coins = os.urandom(32)
            c, cc = Kyber512._cpapke_enc(sender_pkey, message, coins)

            cipher = AES.new(Diffie_Hellman.to_bytes(16, "big"), AES.MODE_CBC)
            iv = cipher.iv
            cipherkey = iv + cipher.encrypt(pad(sender_skey, AES.block_size))

            message_data = {
    "c": c.hex(),  # Convert bytes to hex string
    "cc": cc.hex() if isinstance(cc, bytes) else cc,  # Convert cc if it's bytes
    "cipherkey": cipherkey.hex()
}

            message_data_json = json.dumps(message_data)
            client.publish(MQTT_TOPIC_CHALLENGE_CHALLENGE, message_data_json)
            print("Sent challenge response.")

    elif msg.topic == MQTT_TOPIC_CHALLENGE_RESPONSE:
        if msg.payload.decode() == "questionable":
            Verified = True
            client.publish(MQTT_TOPIC_ACKNOWLEDGMENT, "Challenge Passed")
            print("Challenge verification successful.")

client = mqtt.Client()
client.on_message = on_message
client.connect(MQTT_BROKER, 1883, 60)
client.loop_start()

print("Starting sender...")

# Ensure connection
while not Connected:
    client.publish(MQTT_TOPIC_AVAILABLE, "online")
    client.subscribe(MQTT_TOPIC_CONNECTED)
    print("Waiting for receiver connection...")
    time.sleep(1)

# Perform key exchange
client.publish(MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY, str(A))
while Diffie_Hellman == None:
    client.subscribe(MQTT_TOPIC_DIFFIE_HELLMAN_RECEIVER_KEY)

# Wait for verification
while not Verified:
    if not Requested:
        client.subscribe(MQTT_TOPIC_CHALLENGE_REQUEST)
        print("Waiting for challenge request...")
    
    client.subscribe(MQTT_TOPIC_CHALLENGE_RESPONSE)
    time.sleep(2)

# Send data after verification
while Verified:
    temperature = "20"
    message = temperature.ljust(32, " ").encode()
    c, cc = Kyber512._cpapke_enc(sender_pkey, message, os.urandom(32))
    data = {"c": c.hex(), "cc": cc}
    client.publish(MQTT_TOPIC_DATA_SEND, json.dumps(data))
    print("Sent encrypted temperature data.")
    time.sleep(5)

client.loop_stop()
client.disconnect()
