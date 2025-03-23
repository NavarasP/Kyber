from flask import Flask, render_template, request
import os

app = Flask(__name__)
MESSAGE_FILE = "message.txt"

def save_message_to_file(message):
    """Save the message to the text file."""
    with open(MESSAGE_FILE, "w") as file:
        file.write(message)

@app.route("/", methods=["GET", "POST"])
def index():
    """Render the sender page and handle message submission."""
    if request.method == "POST":
        message = request.form.get("message", "").strip()
        if message:
            save_message_to_file(message)
            return render_template("sender.html")
        else:
            return render_template("sender.html")
    return render_template("sender.html")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5002)