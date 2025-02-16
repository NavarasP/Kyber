from kyber import Kyber512
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
import os
import base64
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

# MQTT Broker & Topics
MQTT_BROKER = "localhost"
MQTT_TOPIC_CHALLENGE_REQUEST = "challenge/request"
MQTT_TOPIC_CHALLENGE_RESPONSE = "challenge/response"
MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY = "diffie_hellman/sender_key"
MQTT_TOPIC_DIFFIE_HELLMAN_RECEIVER_KEY = "diffie_hellman/receiver_key"
MQTT_TOPIC_KYBER_SENDER_SECRET_KEY = "kyber/sender_secret_key"
MQTT_TOPIC_KYBER_RECEIVER_SECRET_KEY = "kyber/receiver_secret_key"
MQTT_TOPIC_DATA_SEND = "data/send"

# Global Variables
Connected = False
Verified = False
Diffie_Hellman = None
private_key_receiver = 15
prime = 23
generator = 5

# Compute receiver's public key (B)
B = pow(generator, private_key_receiver, prime)


def on_message(client, userdata, msg):
    """Callback for receiving messages."""
    global Diffie_Hellman, Verified, Connected

    if msg.topic == MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY:
        A = int(msg.payload.decode())
        print("[Receiver] Received A:", A)
        Diffie_Hellman = pow(A, private_key_receiver, prime)
        client.publish(MQTT_TOPIC_DIFFIE_HELLMAN_RECEIVER_KEY, str(B))
        client.publish(MQTT_TOPIC_CHALLENGE_REQUEST, "CHALLENGE_ME")
        Connected = True

    elif msg.topic == MQTT_TOPIC_CHALLENGE_RESPONSE:
        encrypted_data = json.loads(msg.payload.decode())
        c, cc = base64.b64decode(encrypted_data["c"]), encrypted_data["cc"]
        receiver_skey = Kyber512._cpapke_dec(c, cc, Diffie_Hellman.to_bytes(16, "big"))
        print("[Receiver] Decrypted challenge response:", receiver_skey.decode().strip())

        # Encrypt receiver secret key and send it
        cipher = AES.new(Diffie_Hellman.to_bytes(16, "big"), AES.MODE_CBC)
        iv = cipher.iv
        encrypted_receiver_skey = iv + cipher.encrypt(pad(receiver_skey, AES.block_size))
        client.publish(MQTT_TOPIC_KYBER_RECEIVER_SECRET_KEY, encrypted_receiver_skey.hex(), qos=2)
        Verified = True

    elif msg.topic == MQTT_TOPIC_DATA_SEND:
        encrypted_data = json.loads(msg.payload.decode())
        c, cc = base64.b64decode(encrypted_data["c"]), encrypted_data["cc"]
        decrypted_message = Kyber512._cpapke_dec(c, cc, receiver_skey)
        print("[Receiver] Decrypted Sensor Data:", decrypted_message.decode().strip())


client = mqtt.Client()
client.on_message = on_message
client.connect(MQTT_BROKER, 1883, 60)
client.loop_start()

client.subscribe(MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY)
client.subscribe(MQTT_TOPIC_CHALLENGE_RESPONSE)
client.subscribe(MQTT_TOPIC_KYBER_SENDER_SECRET_KEY)
client.subscribe(MQTT_TOPIC_DATA_SEND)

while not Verified:
    time.sleep(1)

print("[Receiver] Fully authenticated and receiving data.")

client.loop_forever()



@app.route("/connect", methods=["POST"])
def send_data():
    global Connected
    while not Connected:
        client.subscribe(MQTT_TOPIC_DIFFIE_HELLMAN_SENDER_KEY)




        return jsonify({"error": "Verification not complete"}), 400
    
    temperature = request.json.get("temperature", "20")
    message = temperature.ljust(32).encode()
    c, cc = Kyber512._cpapke_enc(sender_pkey, message, os.urandom(32))
    data_json = json.dumps({"c": base64.b64encode(c).decode(), "cc": cc})
    publish_message(MQTT_TOPICS["data_send"], data_json)
    return jsonify({"status": "Data sent"})

@app.route("/status", methods=["GET"])
def get_status():
    return jsonify({"Connected": Connected, "Verified": Verified})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)