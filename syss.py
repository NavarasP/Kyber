from flask import Flask, render_template
from flask_socketio import SocketIO
import paho.mqtt.client as mqtt
import eventlet

eventlet.monkey_patch()

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# MQTT Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 1883

MQTT_TOPIC_CONNECTED = "status/Connected"
MQTT_TOPIC_DH_SENDER_KEY = "diffie_hellman/senderkey"
MQTT_TOPIC_DH_RECEIVER_KEY = "diffie_hellman/receiverkey"

MQTT_TOPIC_CHALLENGE_REQUEST = "challenge/request"
MQTT_TOPIC_CHALLENGE_RESPONSE = "challenge/response"

MQTT_TOPIC_DATA_SEND = "data/send"
MQTT_TOPIC_ACKNOWLEDGMENT = "message/Acknowledged"

Connected = False
Verified = False
Diffie_Hellman = None

# Diffie-Hellman Key Exchange
private_key_receiver = 15
prime = 23
generator = 5
B = pow(generator, private_key_receiver, prime)

def on_message(client, userdata, msg):
    global Connected, Verified, Diffie_Hellman

    print(f"Message received: Topic={msg.topic}, Payload={msg.payload.decode()}")

    if msg.topic == MQTT_TOPIC_DH_SENDER_KEY:
        A = int(msg.payload.decode())
        Diffie_Hellman = pow(A, private_key_receiver, prime)
        print("Received DH key, computed shared key:", Diffie_Hellman)
        client.publish(MQTT_TOPIC_DH_RECEIVER_KEY, str(B))
        time.sleep(2)

    elif msg.topic == MQTT_TOPIC_CHALLENGE_RESPONSE and msg.payload.decode() == "questionable":
        Verified = True
        client.publish(MQTT_TOPIC_ACKNOWLEDGMENT, "Challenge Passed")
        time.sleep(2)

    elif msg.topic == MQTT_TOPIC_DATA_SEND:
        temperature = msg.payload.decode()
        print(f"Received Temperature: {temperature}°C")
        socketio.emit('temperature_update', {"temperature": temperature})

@app.route('/')
def index():
    return render_template('temperature.html')

print("Initializing MQTT Client...")
client = mqtt.Client()
client.on_message = on_message
client.connect(MQTT_BROKER, MQTT_PORT, 60)
client.loop_start()

socketio.run(app, debug=True)
