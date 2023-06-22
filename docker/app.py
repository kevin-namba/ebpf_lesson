from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['GET'])
def heelo():
    return("hello")

app.run(host="0.0.0.0", port=80, debug=True)