from flask import Flask, render_template

app = Flask(__name__)
TEMP_FILE = "temperature.txt"

def get_latest_temperature():
    """Read the latest temperature from the file."""
    try:
        with open(TEMP_FILE, "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        return "No Data"

@app.route("/")
def index():
    """Render the temperature display page."""
    temperature = get_latest_temperature()
    return render_template("index.html", temperature=temperature)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
