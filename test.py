import requests
import time

KEYCLOAK_HEALTHCHECK_URL = "http://localhost:8080/"
KEYCLOAK_TOKEN_URL = "http://localhost:8080/realms/seas8405/protocol/openid-connect/token"
CLIENT_ID = "flask-client"
CLIENT_SECRET = "secret" 
USERNAME = "test-user"
PASSWORD = "password"

PROTECTED_API = "http://localhost:5000/protected"

def wait_for_keycloak(timeout=60, interval=3):
    print("Waiting for Keycloak server to be available...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(KEYCLOAK_HEALTHCHECK_URL)
            if response.status_code == 200:
                print("Keycloak is up.")
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(interval)
    raise TimeoutError(f"Keycloak did not become available within {timeout} seconds.")

def get_access_token():
    data = {
        'grant_type': 'password',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'username': USERNAME,
        'password': PASSWORD
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(KEYCLOAK_TOKEN_URL, data=data, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Failed to get token: {response.status_code}, {response.text}")
    
    return response.json().get("access_token")

def test_protected_api_with_token(token):
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(PROTECTED_API, headers=headers)
    print("\nRequest WITH token:")
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {response.text}")

def test_protected_api_without_token():
    response = requests.get(PROTECTED_API)
    print("\nRequest WITHOUT token:")
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {response.text}")

if __name__ == "__main__":
    try:
        wait_for_keycloak()
        token = get_access_token()
        test_protected_api_with_token(token)
    except Exception as e:
        print(f"Error getting token: {e}")
    
    test_protected_api_without_token()
