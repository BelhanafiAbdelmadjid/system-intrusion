from flask import Flask,redirect
class WEBServer:
    
    def __init__(self,redirect_to:str) -> None:
        '''
            redirect_to => url to redirect the victim to, exemple 'youtube.com'
        '''
        
        self.redirect_to = redirect_to

    def listen(self):
        app = Flask(__name__)

        @app.route("/")
        def home():
            # return redirect(self.redirect_to)
            return "Hello world"
        
        app.run(host='0.0.0.0',port=80,debug=False, use_reloader=False) 
        


if __name__ == "__main__":
    w = WEBServer(redirect_to='youtube.com')
    w.listen()

