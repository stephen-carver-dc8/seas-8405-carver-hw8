from flask import Flask, request, jsonify
from jose import jwt
import requests
import os

app = Flask(__name__)

OIDC_ISSUER = os.getenv("OIDC_ISSUER", "http://localhost:8080/realms/seas8405")
JWKS_URL = f"{OIDC_ISSUER}/protocol/openid-connect/certs"


def get_jwks():
    return requests.get(JWKS_URL).json()


@app.route("/protected")
def protected():
    auth_header = request.headers.get("Authorization", None)
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid token"}), 401

    token = auth_header.split(" ")[1]
    try:
        jwks = get_jwks()
        key = jwks["keys"][0]
        payload = jwt.decode(token, key, algorithms=['RS256'], issuer=OIDC_ISSUER)
        return jsonify({"message": "Access granted", "user": payload.get("preferred_username")})
    except Exception as e:
        return jsonify({"error": "Invalid token", "details": str(e)}), 401


@app.route("/")
def index():
    return "IAM Protected Flask App"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
