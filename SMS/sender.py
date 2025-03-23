from kyber import Kyber512
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
import time

# MQTT Broker & Topics
MQTT_BROKER = "localhost"
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
challenge = None
challenge_response_message = None
prime = 23
generator = 5
private_key_sender = 6
B = None
Diffie_Hellman = None
receiver_skey = None

sender_pkey, sender_skey = Kyber512._cpapke_keygen()

# MQTT Client
client = mqtt.Client()


def on_connect(client, userdata, flags, rc):
    """Callback for successful connection to the broker."""
    if rc == 0:
        print("Connected to MQTT Broker")
    else:
        print("Failed to connect, return code:", rc)


def on_message(client, userdata, msg):
    """Callback for receiving messages."""
    global challenge, B, challenge_response_message, receiver_skey, Diffie_Hellman

    if msg.topic == MQTT_TOPIC_DIFFIE_HELLMAN_RECIVER_KEY:
        B = int(msg.payload.decode())
        print("Received B:", B)
        Diffie_Hellman = pow(B, private_key_sender, prime)
        print("Calculated Diffie-Hellman Key:", Diffie_Hellman)

    elif msg.topic == MQTT_TOPIC_CHALLENGE_REQUEST:
        challenge = msg.payload.decode()
        print("Received Challenge Request:", challenge)

    elif msg.topic == MQTT_TOPIC_CHALLENGE_RESPONCE:
        challenge_response_message = msg.payload.decode()
        print("Received Challenge Response:", challenge_response_message)

    elif msg.topic == MQTT_TOPIC_KYBER_RECIVER_SECRET_KEY:
        ciphertext = bytes.fromhex(msg.payload.decode())
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(Diffie_Hellman.to_bytes(16, "big"), AES.MODE_CBC, iv)
        receiver_skey = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
        print("Received and Decrypted Receiver Secret Key")


def on_publish(client, userdata, mid):
    """Callback for confirming a message was published."""
    print(f"Message {mid} published successfully")




# Configure Callbacks
client.on_connect = on_connect
client.on_message = on_message
client.on_publish = on_publish

# Connect to MQTT Broker
client.connect(MQTT_BROKER, 1883, 60)
client.loop_start()

# Step 1: Send Diffie-Hellman Public Key (A)
A = pow(generator, private_key_sender, prime)
print("Publishing A:", A)
info = client.publish(MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY, str(A))
info.wait_for_publish()  # Ensure message is published

# Step 2: Subscribe to Receiver's Diffie-Hellman Key (B)
client.subscribe(MQTT_TOPIC_DIFFIE_HELLMAN_RECIVER_KEY)
time.sleep(2)  # Allow time for B to be received

# Step 3: Send Challenge Request
print("Publishing Challenge Request")
info = client.publish(MQTT_TOPIC_CHALLENGE_REQUEST, "CHALLENGE_ME")
info.wait_for_publish()

# Step 4: Subscribe to Challenge Response
client.subscribe(MQTT_TOPIC_CHALLENGE_CHALLENGE)
time.sleep(2)  

# Step 5: Encrypt and Send Secret Key
if challenge == "CHALLENGE_ME":
    message = "abbreviationunquestionablexyzabcdef"
    c, cc = Kyber512._cpapke_enc(sender_pkey, message)
    data = {"c": c, "cc": cc}
    data_json = json.dumps(data)

    print("Publishing Challenge Data")
    info = client.publish(MQTT_TOPIC_CHALLENGE_CHALLENGE, data_json)
    info.wait_for_publish()

    # Encrypt Sender Secret Key with AES and Send
    cipher = AES.new(Diffie_Hellman.to_bytes(16, "big"), AES.MODE_CBC)
    iv = cipher.iv
    cipherkey = iv + cipher.encrypt(pad(sender_skey.encode(), AES.block_size))

    print("Publishing Kyber Sender Secret Key")
    info = client.publish(MQTT_TOPIC_KYBER_SENDER_SECRET_KEY, cipherkey.hex())
    info.wait_for_publish()

# Step 6: Subscribe to Receiver Secret Key
client.subscribe(MQTT_TOPIC_KYBER_RECIVER_SECRET_KEY)
time.sleep(2)

# Step 7: Verify Challenge Response
if challenge_response_message == "questionable":
    Connected = True
    print("Connection Successful")

# Step 8: Continuous Data Transmission
while Connected:
    # Read message from a text file
    file_path = "message.txt"  # Path to the text file
    message = "read_message_from_file(file_path)"
    if message:
        # Pad the message to 32 bytes (or any required length)
        message = message.ljust(32, " ").encode()
        c, cc = Kyber512._cpapke_enc(sender_pkey, message)
        data = {"c": c, "cc": cc}
        data_json = json.dumps(data)

        print("Publishing Message Data")
        info = client.publish(MQTT_TOPIC_DATA_SEND, data_json)
        info.wait_for_publish()
    else:
        print("No message found in the file.")

    time.sleep(5)

client.loop_stop()
client.disconnect()
