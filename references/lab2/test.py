import requests

KEYCLOAK_URL = "http://localhost:8080/realms/FintechApp/protocol/openid-connect/token"
CLIENT_ID = "flask-client"
CLIENT_SECRET = "secret"
USERNAME = "testuser"
PASSWORD = "password"
PROTECTED_URL = "http://localhost:15000"

response = requests.get(PROTECTED_URL)
print("Response from protected endpoint without token:")
print(response.text)

data = {
    'grant_type': 'password',
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'username': USERNAME,
    'password': PASSWORD,
}

response = requests.post(KEYCLOAK_URL, data=data)
if response.status_code != 200:
    print(f"Failed to retrieve access token: {response.status_code}")
    print(response.text)
    exit(1)

access_token = response.json().get('access_token')
if not access_token:
    print("Access token not found in response.")
    print(response.json())
    exit(1)

headers = {
    'Authorization': f'Bearer {access_token}'
}

response = requests.get(PROTECTED_URL, headers=headers)
print("Response from protected endpoint with token:")
print(response.text)
