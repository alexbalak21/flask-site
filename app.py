from flask import Flask, request, jsonify

app = Flask(__name__)

# Simple GET route
@app.route("/", methods=["GET"])
def hello_world():
    return "<h1>Hello from Flask v3</h1>"

# GET API endpoint
@app.route("/api/message", methods=["GET"])
def get_message():
    return jsonify(message="Hello from the GET endpoint")

# POST API endpoint
@app.route("/api/message", methods=["POST"])
def post_message():
    data = request.get_json()  # read JSON body
    name = data.get("name", "Anonymous")
    return jsonify(response=f"Hello {name}, your POST worked!")