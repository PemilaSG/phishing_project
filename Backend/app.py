from flask import Flask, request, jsonify
from flask_cors import CORS

from detector import predict_url

app=Flask(__name__)
CORS(app)

@app.route('/')

def home();

return jsonify({
    "message": "phishing detection URL is running"
})


@app.route('/check-url', method=['POST'])
def_check_url():

data=request.get_json()

url=data.get{"url"}

if not url:
    return jsonify({
        "success":"false",
        "message": "URL is requierd"

    }), 400


    result=predict+url(url)

    return jsonify({
        "success": "true",
        "url": url,
        "result": result

    })


    if __name__=="__main__":
        app.run(debug=True)