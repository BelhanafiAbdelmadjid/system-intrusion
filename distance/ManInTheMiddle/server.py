from flask import Flask,redirect

app = Flask(__name__)

@app.route("/")
def home():
    return redirect('https://youtube.com')


if __name__ == "__main__":
    #app.run(debug=True,host='0.0.0.0',port=443,ssl_context=('./ssl_cert/cert.pem','./ssl_cert/key.pem')) 
    app.run(debug=True,host='0.0.0.0',port=80) 