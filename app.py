import os, pathlib
import requests
from flask import Flask, session, abort, redirect, request, render_template, url_for
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from pip._vendor import cachecontrol
from dotenv import load_dotenv

load_dotenv()   # load .env

app = Flask("Google Login App")
app.secret_key = os.environ.get("APP_SECRET_KEY") 
# python -c 'import secrets; print(secrets.token_hex())'
print(f'>>> APP_SECRET_KEY : {app.secret_key}')

# https 만을 지원하는 기능을 http에서 테스트할 때 필요한 설정
# to allow Http traffic for local dev
# 개발환경에만 적용. 보안 연결이 활성화되지 않은 트랜스포트를 허용한다는 것을 의미
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

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


@app.route("/")
@app.route("/index.html")
def index():
    # return "Hello World <a href='/login'><button>Login</button></a>"
    return render_template('index.html')


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    try:
        # Fetch token using authorization response
        flow.fetch_token(authorization_response=request.url)
        
        # Verify state to prevent CSRF attacks
        if session.get("state") != request.args.get("state"):
            abort(500)  # State does not match!
        
        # Get credentials
        credentials = flow.credentials
        
        # Create a request session with caching
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        
        # Create token request for Google authentication
        token_request = google.auth.transport.requests.Request(session=cached_session)
        
        # Verify ID token to get user information
        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=GOOGLE_CLIENT_ID
        )
        
        # Store user ID and name in session
        session["google_id"] = id_info.get("sub")
        session["name"] = id_info.get("name")
        session["email"] = id_info.get("email")
        session["picture"] = id_info.get("picture")
        
        # Redirect user to protected area
        return redirect("/protected_area")
    except Exception as e:
        # Handle exceptions gracefully
        return f"An error occurred: {e}", 500


@app.route("/logout")
def logout():
    session.pop('google_id', None)
    session.pop('name', None)
    
    # Then clear the rest of the session
    session.clear()

    # Revoke OAuth token (optional)
    revoke_token()  # 선택적으로 OAuth 토큰을 폐기할 수 있음.
                    # 이는 사용자가 로그아웃한 후에 액세스 토큰을 더 이상 사용하지 못하게 하는데 도움이 됨
                    # 이 함수는 토큰 폐기에 필요한 인증 서버의 엔드포인트에 요청을 보내는 작업을 수행함
                    # 사용하는 OAuth 제공자에 따라 이 기능을 지원하지 않을 수 있음
    
    
    return redirect("/")


@app.route("/protected_area")
@login_is_required
def protected_area():
    try:
        # Construct a greeting message with more user information
        greeting_message = f""
        greeting_message += f"<h1>Hello</h1>"
        greeting_message += f"Your GoogleID  : {session['google_id']}!<br/>"
        greeting_message += f"Your name  : {session['name']}!<br/>"
        greeting_message += f"Your email : {session['email']}<br/>"
        greeting_message += f"<img src='{session['picture']}' alt='Profile Picture'><br/></br/>"
        greeting_message += "<a href='/logout'><button>Logout</button></a>"
        
        return greeting_message
    except Exception as e:
        # Handle exceptions gracefully
        return f"An error occurred: {e}", 500


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000, debug=True)