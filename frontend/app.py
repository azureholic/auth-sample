import jwt
import os
import msal
from flask import Flask, render_template, abort, request, jsonify
from functools import wraps
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
app = Flask(__name__)


def get_user_name():
    userName = request.headers.get('X-Ms-Client-Principal-Name')
    if not userName:
        return 'Anonymous'
    return userName


def get_current_user_role():
    token = request.headers.get('X-Ms-Token-Aad-Id-Token')
    try:
        # Decode the token without verification (since we trust EasyAuth)
        decodedToken = jwt.decode(token, options={"verify_signature": False})
        roles = decodedToken.get('roles', [])
        print(roles)
        return roles
    except jwt.DecodeError:
        return None

def get_token_for_api():
    idToken = request.headers.get('X-Ms-Token-Aad-Id-Token')
    scopes = ["api://kpn_auth_api/.default"]
    
    #This example only uses the default memory token cache and should not be used for production
    msal_client = msal.ConfidentialClientApplication(
            client_id=os.environ.get("CLIENT_ID"),
            authority=os.environ.get("AUTHORITY"),
            client_credential=os.environ.get("CLIENT_SECRET"))
    
    #acquire token on behalf of the user that called this API
    apiAccessInfo = msal_client.acquire_token_on_behalf_of(
        user_assertion=idToken,
        scopes=scopes
    )
    return apiAccessInfo["access_token"]

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if role not in get_current_user_role():
                print('role:' + role)
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/')
def home():
    return render_template('home.html', user_name=get_user_name())

@app.route('/admin')
@role_required('app-admin')
def admin():
    return render_template('admin.html', api_access_token=get_token_for_api())

@app.route('/user')
@role_required('app-user')
def user():
    return render_template('user.html')


if __name__ == '__main__':
    app.run(debug=True)