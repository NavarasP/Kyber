from kyber import Kyber512
from PUFKey import get_puf_key
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
import time

# MQTT Broker & Topics
MQTT_BROKER = "192.168.30.105"
MQTT_TOPIC_CHALLENGE_REQUEST = "challenge/request"
MQTT_TOPIC_CHALLENGE_CHALLENGE = "challenge/challenge"
MQTT_TOPIC_CHALLENGE_RESPONCE = "challenge/responce"
MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY = "deffie_hellman/senderkey"
MQTT_TOPIC_DIFFIE_HELLMAN_RECIVER_KEY = "deffie_hellman/reciverkey"
MQTT_TOPIC_KYBER_SENDER_SECRET_KEY = "sender/secretkey"
MQTT_TOPIC_KYBER_RECIVER_SECRET_KEY = "sender/secretkey"
MQTT_TOPIC_DATA_SEND = "data/send"

# Global Variables
Connected = False
Verified = False
sender_skey = None
Diffie_Hellman = None
private_key_receiver = 15
prime = 23
generator = 5
A = None

def on_connect(client, userdata, flags, rc, properties):
    global Connected
    if rc == 0:
        print("Connected to MQTT Broker")
        Connected = True
        client.subscribe(MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY)
        client.subscribe(MQTT_TOPIC_KYBER_SENDER_SECRET_KEY)
        client.subscribe(MQTT_TOPIC_CHALLENGE_CHALLENGE)
        client.subscribe(MQTT_TOPIC_DATA_SEND)
    else:
        print(f"Failed to connect, return code {rc}")

def on_message(client, userdata, msg):
    global A, Diffie_Hellman, sender_skey, Verified

    if msg.topic == MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY:
        A = int(msg.payload.decode())
        print("Received A:", A)
        B = pow(generator, private_key_receiver, prime)
        Diffie_Hellman = pow(A, private_key_receiver, prime)
        print("Calculated Diffie-Hellman Key:", Diffie_Hellman)
        client.publish(MQTT_TOPIC_DIFFIE_HELLMAN_RECIVER_KEY, str(B))
        
    elif msg.topic == MQTT_TOPIC_KYBER_SENDER_SECRET_KEY:
        ciphertext = bytes.fromhex(msg.payload.decode())
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(Diffie_Hellman.to_bytes(16, "big"), AES.MODE_CBC, iv)
        sender_skey = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
        print("Received and Decrypted Sender Secret Key")
    
    elif msg.topic == MQTT_TOPIC_CHALLENGE_CHALLENGE:
        challenge_data = json.loads(msg.payload.decode())
        print("Received Challenge Data")
        client.publish(MQTT_TOPIC_CHALLENGE_RESPONCE, "questionable")
        Verified = True
    
    elif msg.topic == MQTT_TOPIC_DATA_SEND:
        data = json.loads(msg.payload.decode())
        c = bytes.fromhex(data["c"])
        cc = data["cc"]
        message = Kyber512._cpapke_dec(sender_skey, c, cc)
        print("Decrypted Sensor Data:", message.decode().strip())

# Initialize MQTT Client
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message

client.connect(MQTT_BROKER, 1883, 60)
client.loop_start()

while not Connected:
    print("Waiting for connection...")
    time.sleep(1)

while not Verified:
    print("Waiting for verification...")
    time.sleep(1)

print("Secure Communication Established")

while Verified:
    time.sleep(5)

client.loop_stop()
client.disconnect()
