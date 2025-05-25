import os
from flask import Flask, redirect, url_for, session, jsonify, request, render_template_string
from authlib.integrations.flask_client import OAuth
from authlib.jose import JsonWebKey, jwt
import requests
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "change-me")

oauth = OAuth(app)

keycloak = oauth.register(
    name='keycloak',
    client_id=os.environ.get("KEYCLOAK_CLIENT_ID"),
    client_secret=os.environ.get("KEYCLOAK_CLIENT_SECRET"),
    server_metadata_url=f'{os.environ.get("KEYCLOAK_URL")}/realms/{os.environ.get("KEYCLOAK_REALM")}/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

@app.route('/')
def homepage():
    return 'Welcome! <a href="/login">Login</a>'

@app.route('/login')
def login():
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce
    redirect_uri = url_for('auth', _external=True)
    return keycloak.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/auth')
def auth():
    token = keycloak.authorize_access_token()
    nonce = session.get('nonce')
    userinfo = keycloak.parse_id_token(token, nonce=nonce)
    session['user'] = userinfo
    return redirect('/profile')

@app.route('/profile')
def profile():
    if 'user' in session:
        user_info = session['user']
        return render_template_string("""
            <h1>You are logged in! Here is your info:</h1>
            <pre>{{ user_info | tojson(indent=2) }}</pre>
            <form action="/logout" method="get">
                <button type="submit">Logout</button>
            </form>
        """, user_info=user_info)
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/protected')
def protected():
    auth = request.headers.get('Authorization', None)
    if not auth:
        return jsonify({'error': 'Missing token'}), 401

    token = auth.split(" ")[1]
    jwks_uri = f"{os.environ['KEYCLOAK_URL']}/realms/{os.environ['KEYCLOAK_REALM']}/protocol/openid-connect/certs"
    jwks = requests.get(jwks_uri).json()
    key_set = JsonWebKey.import_key_set(jwks)

    try:
        claims = jwt.decode(token, key_set)
        claims.validate()
        return jsonify(claims)
    except Exception as e:
        return jsonify({'error': 'Invalid token', 'message': str(e)}), 401

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
