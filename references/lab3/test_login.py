import requests
from bs4 import BeautifulSoup

# Initial request to SSO login page
print("[*] Initiating SAML login...")
# r = requests.get("http://localhost:15001/sso/login", allow_redirects=True)
r = requests.get("http://localhost:15001/sso/login", allow_redirects=True)


if r.status_code != 200:
    raise Exception(f"[!] Login page failed to load: {r.status_code}")

# Extract form action and inputs
soup = BeautifulSoup(r.text, "html.parser")
form = soup.find("form")
if not form:
    raise Exception("[!] No login form found.")

action_url = form.get("action")
inputs = {tag.get("name"): tag.get("value", "") for tag in form.find_all("input")}
inputs["username"] = "jdoe"
inputs["password"] = "password"

print("[*] Submitting credentials to Keycloak...")
r2 = requests.post(action_url, data=inputs, allow_redirects=True)

if "Welcome" in r2.text or "You are logged in" in r2.text:
    print("[✓] Login successful!")
else:
    print("[✗] Login failed or SAML response not received.")

