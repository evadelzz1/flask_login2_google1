import os, pathlib
import requests
from flask import Flask, session, abort, redirect, request, render_template, url_for
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from pip._vendor import cachecontrol
from dotenv import load_dotenv

# load .env
load_dotenv()

app = Flask("Google Login App")
app.secret_key = os.environ.get("APP_SECRET_KEY") 
# python -c 'import secrets; print(secrets.token_hex())'
print(f'>>> APP_SECRET_KEY : {app.secret_key}')

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"     # 개발환경에만 적용. 보안 연결이 활성화되지 않은 트랜스포트를 허용한다는 것을 의미

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
    redirect_uri="http://localhost:3000/callback"
)

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    # if not session["state"] == request.args["state"]:
    #     abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")


@app.route("/logout")
def logout():
    session.pop('google_id', None)
    session.pop('name', None)
    
    # Then clear the rest of the session
    session.clear()
    return redirect("/")


@app.route("/")
@app.route("/index.html")
def index():
    # return "Hello World <a href='/login'><button>Login</button></a>"
    return render_template('index.html')

@app.route("/protected_area")
@login_is_required
def protected_area():
    return f"Hello {session['name']}! <br/> <a href='/logout'><button>Logout</button></a>"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000, debug=True)