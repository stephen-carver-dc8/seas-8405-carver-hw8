# SEAS 8405 Homework 8: Secure IAM Architecture

This project demonstrates a secure Identity and Access Management (IAM) architecture using Keycloak as an identity provider and a protected Flask microservice. The system enforces authentication and authorization using OAuth 2.0 and OpenID Connect (OIDC).

---

## Architecture Overview

* **Keycloak** (Identity Provider): Provides user authentication and token issuance.
* **Flask App** (Resource Server): Secures routes by validating JWTs using Keycloak’s public keys.
* **Docker Compose**: Manages deployment of Keycloak and Flask in a consistent environment.

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/stephen-carver-dc8/seas-8405-carver-hw8.git
cd seas-8405-carver-hw8
```

### 2. Start the Environment

```bash
make reset
```

This will:

* Build the Flask app
* Start Keycloak with pre-configured realm/client/user via realm export
* Expose Flask on `http://localhost:5000`

### 3. Keycloak Access

* **Admin UI**: `http://localhost:8080`
* **Username**: `admin`, **Password**: `admin`
* **Realm**: `seas8405`
* **Client**: `flask-client` (confidential)
* **Test User**: `test-user` / `password`

---
## Website Useage

* The Flask app has a home page that redirects to Keycloak login
* If successfully authenticated, shows users profile information

### Sample Log-in

```
http://localhost:5000
```

---

## API Protection

* The Flask app validates JWTs from the `Authorization: Bearer <token>` header.
* The JWKS endpoint from Keycloak is used to verify the token signature.

### Sample Protected Route

```bash
curl -H "Authorization: Bearer <your_token>" http://localhost:5000/protected
```

### Without Token

```bash
curl http://localhost:5000/protected
# -> 401 Unauthorized
```

---

## References

* [Keycloak Documentation](https://www.keycloak.org/docs/latest/)
* [AuthLib Documentation](https://github.com/authlib/authlib/blob/main/tests/clients/test_flask/test_oauth_client.py)
* Based on course Labs: [Lab1](./references/lab1/), [Lab2](./references/lab2/), [Lab3](./references/lab3/)

---

## Testing Summary
* `make reset` reliably resets and tests the environment
* Python Test
```python
test.py
```
* Tokens are validated correctly
* Invalid or missing tokens are rejected
* Realm and client are imported automaticall
---

For threat modeling and mitigation strategies, see [report.md](./deliverables/report.md).
