from kyber import Kyber512
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
import time
import os
import base64

# MQTT Broker & Topics
MQTT_BROKER = "localhost"
MQTT_TOPIC_CHALLENGE_REQUEST = "challenge/request"
MQTT_TOPIC_CHALLENGE_CHALLENGE = "challenge/challenge"
MQTT_TOPIC_CHALLENGE_RESPONSE = "challenge/response"
MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY = "diffie_hellman/senderkey"
MQTT_TOPIC_DIFFIE_HELLMAN_RECEIVER_KEY = "diffie_hellman/receiverkey"
MQTT_TOPIC_KYBER_SENDER_SECRET_KEY = "sender/secretkey"
MQTT_TOPIC_KYBER_RECEIVER_SECRET_KEY = "receiver/secretkey"
MQTT_TOPIC_DATA_SEND = "data/send"

# Global Variables
Connected = False
Verified = False
challenge = None
private_key_sender = 6
prime = 23
generator = 5
Diffie_Hellman = None

# Generate Diffie-Hellman public key (A)
A = pow(generator, private_key_sender, prime)

# Generate Kyber Keys
PUF = os.urandom(32)
sender_pkey, sender_skey = Kyber512._cpapke_keygen(PUF)

# Encrypt challenge message
message = bytes("abbreviationunquestionablexyz".ljust(32), "utf-8")
coins = os.urandom(32)
c, cc = Kyber512._cpapke_enc(sender_pkey, message, coins)
message_data = {"c": base64.b64encode(c).decode("utf-8"), "cc": cc}
message_data_json = json.dumps(message_data)

def on_message(client, userdata, msg):
    """Callback for receiving messages."""
    global Diffie_Hellman, Verified, Connected

    if msg.topic == MQTT_TOPIC_DIFFIE_HELLMAN_RECEIVER_KEY:
        B = int(msg.payload.decode())
        print("Received B:", B)
        Diffie_Hellman = pow(B, private_key_sender, prime)
        Connected = True  # Ensure connection is marked as True

        # Encrypt sender_skey using AES
        cipher = AES.new(Diffie_Hellman.to_bytes(16, "big"), AES.MODE_CBC)
        iv = cipher.iv
        cipherkey = iv + cipher.encrypt(pad(sender_skey.encode(), AES.block_size))

        print("Calculated Diffie-Hellman Key:", Diffie_Hellman)

    elif msg.topic == MQTT_TOPIC_CHALLENGE_REQUEST:
        challenge = msg.payload.decode()
        if challenge == "CHALLENGE_ME" and Connected:
            client.publish(MQTT_TOPIC_CHALLENGE_CHALLENGE, message_data_json)
            client.publish(MQTT_TOPIC_KYBER_SENDER_SECRET_KEY, cipherkey.hex(), qos=2)
            client.subscribe(MQTT_TOPIC_CHALLENGE_RESPONSE)
            client.subscribe(MQTT_TOPIC_KYBER_RECEIVER_SECRET_KEY)

    elif msg.topic == MQTT_TOPIC_CHALLENGE_RESPONSE:
        challenge_response_message = msg.payload.decode()
        if challenge_response_message == "questionable":
            Verified = True
            print("Verified Challenge Response:", challenge_response_message)

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_message = on_message
client.connect(MQTT_BROKER, 1883, 60)
client.loop_start()

# Send initial Diffie-Hellman Key
while not Connected:
    client.publish(MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY, str(A))
    client.subscribe(MQTT_TOPIC_DIFFIE_HELLMAN_RECEIVER_KEY)

# Data transmission after verification
while Verified:
    temperature = "20"
    message = temperature.ljust(32, " ").encode()
    c, cc = Kyber512._cpapke_enc(sender_pkey, message, os.urandom(32))
    data = {"c": base64.b64encode(c).decode("utf-8"), "cc": cc}
    data_json = json.dumps(data)

    print("Publishing Sensor Data")
    client.publish(MQTT_TOPIC_DATA_SEND, data_json)
    time.sleep(5)

