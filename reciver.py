
import json
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from kyber import Kyber512
import os
import time
import threading
TEMP_FILE = "temperature.txt"


MQTT_BROKER = "localhost"

MQTT_TOPIC_AVAILABLE = "status/Available/Device1"
MQTT_TOPIC_CONNECTED = "status/Connected"

MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY = "diffie_hellman/senderkey"
MQTT_TOPIC_DIFFIE_HELLMAN_RECEIVER_KEY = "diffie_hellman/receiverkey"

MQTT_TOPIC_CHALLENGE_REQUEST = "challenge/request"
MQTT_TOPIC_CHALLENGE_CHALLENGE = "challenge/challenge"
MQTT_TOPIC_CHALLENGE_RESPONSE = "challenge/response"

MQTT_TOPIC_DATA_SEND = "data/send"
MQTT_TOPIC_ACKNOWLEDGMENT = "message/Acknowledged"

# Shared variables with locks
devices = []
Connected = False
Verified = False
Requested = False
satis=False
Diffie_Hellman = None
sender_skey = None

lock = threading.Lock()

private_key_receiver = 15
prime = 23
generator = 5
B = pow(generator, private_key_receiver, prime)

def save_temperature(temp):
    """Save temperature data to a text file."""
    with open(TEMP_FILE, "w") as file:  
        file.write(temp)

def on_message(client, userdata, msg):
    global Connected, devices, Diffie_Hellman, Verified, sender_skey, satis

    with lock:
        print(f"Received message: {msg.topic} - {msg.payload.decode()}")

        if msg.topic == MQTT_TOPIC_AVAILABLE:
            client.publish(MQTT_TOPIC_CONNECTED, "Connected")
            Connected = True
            print("Device connected.")

        elif msg.topic == MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY:
            A = int(msg.payload.decode())
            Diffie_Hellman = pow(A, private_key_receiver, prime)
            print(f"Received A: {A}, Computed Shared Key: {Diffie_Hellman}")
            client.publish(MQTT_TOPIC_DIFFIE_HELLMAN_RECEIVER_KEY, str(B), qos=1)


        elif msg.topic == MQTT_TOPIC_CHALLENGE_CHALLENGE:
            data = json.loads(msg.payload.decode())
            cipherkey = bytes.fromhex(data["cipherkey"])
            c = bytes.fromhex(data["c"])
            cc = data["cc"]

            iv = cipherkey[:AES.block_size]
            cipher = AES.new(Diffie_Hellman.to_bytes(16, "big"), AES.MODE_CBC, iv)
            sender_skey = unpad(cipher.decrypt(cipherkey[AES.block_size:]), AES.block_size)
            message = Kyber512._cpapke_dec(sender_skey, c, cc)

            print("Decrypted Challenge Message:", message.decode().strip())
            client.publish(MQTT_TOPIC_CHALLENGE_RESPONSE, "questionable")
            client.subscribe(MQTT_TOPIC_ACKNOWLEDGMENT)

        elif msg.topic == MQTT_TOPIC_ACKNOWLEDGMENT:
            payload = msg.payload.decode()
            if payload == "Challenge Passed":
                Requested = True
                Verified = True
                print("Device verification successful.")
            elif payload == "Device Connected":
                Connected = True
                print("Device connected successfully.")
            elif payload == "B Received":
                satis = True

        elif msg.topic == MQTT_TOPIC_DATA_SEND:
            data = json.loads(msg.payload.decode())
            c = bytes.fromhex(data["c"])
            cc = data["cc"]
            message = Kyber512._cpapke_dec(sender_skey, c, cc)
            save_temperature(str(message.decode().strip()))

            print(f"Received Sensor Data: {message.decode().strip()} °C")

print("Initializing MQTT Client...")
client = mqtt.Client()
client.on_message = on_message
client.connect(MQTT_BROKER, 1883, 60)

client.loop_start()

while not Connected:
    print("Waiting for connection...")
    client.subscribe(MQTT_TOPIC_AVAILABLE)
    time.sleep(1)

while not Verified:
    if Diffie_Hellman is None:
        print("Starting Diffie-Hellman key exchange...")
        client.subscribe(MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY)

    if not Requested:
        client.publish(MQTT_TOPIC_CHALLENGE_REQUEST, "CHALLENGE_ME")
        client.subscribe(MQTT_TOPIC_CHALLENGE_CHALLENGE)
        

    time.sleep(1)

client.subscribe(MQTT_TOPIC_DATA_SEND)

print("Receiver started and listening for data...")
while True:
    time.sleep(5)
