import paho.mqtt.client as mqtt
from kyber import Kyber512
import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time

# MQTT Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 1883

MQTT_TOPIC_AVAILABILITY = "status/Available/Device1"
MQTT_TOPIC_CONNECTED = "status/Connected"

MQTT_TOPIC_DH_SENDER_KEY = "diffie_hellman/senderkey"
MQTT_TOPIC_DH_RECEIVER_KEY = "diffie_hellman/receiverkey"

MQTT_TOPIC_CHALLENGE_REQUEST = "challenge/request"
MQTT_TOPIC_CHALLENGE_RESPONSE = "challenge/response"

MQTT_TOPIC_DATA_SEND = "data/send"
MQTT_TOPIC_ACKNOWLEDGMENT = "message/Acknowledged"

# Flags
Connected = False
Verified = False
Diffie_Hellman = None

# Diffie-Hellman Key Exchange
private_key_sender = 6
prime = 23
generator = 5
A = pow(generator, private_key_sender, prime)

PUF = os.urandom(32)
sender_pkey, sender_skey = Kyber512._cpapke_keygen(PUF)

def on_message(client, userdata, msg):
    global Connected, Diffie_Hellman, Verified

    print(f"Message received: Topic={msg.topic}, Payload={msg.payload.decode()}")

    if msg.topic == MQTT_TOPIC_CONNECTED:
        Connected = True

    elif msg.topic == MQTT_TOPIC_DH_RECEIVER_KEY:
        B = int(msg.payload.decode())
        Diffie_Hellman = pow(B, private_key_sender, prime)
        print("Computed shared DH key:", Diffie_Hellman)
        time.sleep(2)

    elif msg.topic == MQTT_TOPIC_CHALLENGE_REQUEST:
        challenge = msg.payload.decode()
        print("Challenge request received:", challenge)

        if challenge == "CHALLENGE_ME":
            client.publish(MQTT_TOPIC_CHALLENGE_RESPONSE, "questionable")
            print("Challenge response sent.")
            time.sleep(3)

    elif msg.topic == MQTT_TOPIC_ACKNOWLEDGMENT and msg.payload.decode() == "Challenge Passed":
        Verified = True
        print("Challenge verification successful.")
        time.sleep(2)

client = mqtt.Client()
client.on_message = on_message
client.connect(MQTT_BROKER, MQTT_PORT, 60)
client.loop_start()

# Wait for connection
client.publish(MQTT_TOPIC_AVAILABILITY, "online")
client.subscribe(MQTT_TOPIC_CONNECTED)
print("Waiting for connection...")
time.sleep(3)

# Perform Diffie-Hellman Key Exchange
client.publish(MQTT_TOPIC_DH_SENDER_KEY, str(A))
client.subscribe(MQTT_TOPIC_DH_RECEIVER_KEY)
print("Waiting for receiver's DH key...")
time.sleep(5)

# Wait for challenge verification
client.subscribe(MQTT_TOPIC_CHALLENGE_REQUEST)
print("Waiting for challenge request...")
time.sleep(5)

while not Verified:
    time.sleep(1)

# Send temperature data
while Verified:
    temperature = "20"
    client.publish(MQTT_TOPIC_DATA_SEND, temperature)
    print(f"Sent Temperature: {temperature}°C")
    time.sleep(5)

client.loop_stop()
client.disconnect()
