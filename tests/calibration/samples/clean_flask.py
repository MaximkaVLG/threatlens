
from flask import Flask, render_template, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/data")
def get_data():
    return jsonify({"status": "ok", "items": [1, 2, 3]})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
