from flask import Flask, request, jsonify
from flask_cors import CORS

from detector import predict_url

app = Flask(__name__)
CORS(app)


@app.route('/')
def home():
    return jsonify({
        "message": "phishing detection URL is running"
    })


@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.get_json(silent=True) or {}
    url = data.get('url')

    if not url:
        return jsonify({
            "success": False,
            "message": "URL is required"
        }), 400

    result = predict_url(url)

    return jsonify({
        "success": True,
        "url": url,
        "result": result
    })


if __name__ == '__main__':
    app.run(debug=True)