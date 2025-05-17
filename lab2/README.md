
# Lab 1: OAuth 2.0 and OpenID Connect (OIDC) with Keycloak for Secure Microservices

## Introduction

This lab demonstrates how to implement secure authentication and authorization using OAuth 2.0 and OpenID Connect in a microservices environment. You will deploy Keycloak as an identity provider (IdP), configure it with a realm, client, and user, and connect it to a protected Flask API. The lab also provides insights into real-world breaches involving these protocols and emphasizes key security best practices.

---

## Case Study: Okta Security Breaches (2022–2023)

**Overview:**  
Okta, a major identity and access management provider, experienced multiple breaches that directly impacted customer environments and exposed session artifacts.

**Timeline:**
- **March 2022:** The LAPSUS$ group compromised Okta via a third-party support provider.
- **October 2023:** Session artifacts, including HAR files containing tokens, were exposed. Attackers gained admin-level access to downstream SaaS platforms.

**Key Technologies Involved:**
- OAuth 2.0 bearer tokens
- OpenID Connect ID tokens
- Session cookies

**Root Causes:**
- Poor control over third-party access
- Lack of protections for session tokens
- Absence of binding tokens to client origin or device

**Mitigation Lessons:**
- Treat tokens with the same protection level as passwords
- Implement token expiration and revocation policies
- Use origin-bound tokens and ensure TLS is enforced
- Minimize third-party privilege and exposure

---

## Background Concepts

### Authentication

Authentication verifies a user's identity before granting access.

**Why It Matters:**
- Prevent unauthorized access
- Enable audit and traceability
- Enforce personalization and compliance

**Common Methods:**

| Method             | Description                                     |
|--------------------|-------------------------------------------------|
| Passwords          | Easily phished; vulnerable without MFA          |
| OTPs               | Time-sensitive codes via SMS/app                |
| Biometrics         | Physical characteristics (e.g., face, fingerprint) |
| Hardware Tokens    | USB or NFC-based tokens (e.g., YubiKey)         |
| Passkeys           | Cryptographic FIDO2-based passwordless login    |
| Certificates       | X.509-based authentication                      |
| Social Login       | OAuth-based identity delegation (e.g., Google)  |

---

### OAuth (1.0, 2.0, 2.1, 3.0)

OAuth is a protocol for delegated authorization. It allows applications to access user resources without exposing credentials.

**Versions Overview:**
- **OAuth 1.0:** Secure but complex (signed requests)
- **OAuth 2.0:** Widely adopted; uses bearer tokens
- **OAuth 2.1:** Consolidates best practices (e.g., removes implicit flow)
- **OAuth 3.0:** Early-stage conceptual evolution of 2.x

**Use Cases:**
- Third-party API access (e.g., Google Calendar)
- Delegated resource access in microservices
- Identity federation

**Usage Flow:**
1. Application requests access via IdP
2. User authorizes request
3. Application receives access token
4. Token is used to access protected resources

**Risks:**
- Token theft and replay attacks
- Lack of introspection or revocation
- Misconfigured scopes or token reuse

**Best Practices:**
- Always use TLS
- Implement token expiration and revocation
- Use PKCE with public clients
- Validate `iss`, `aud`, and `exp` claims

---

### OpenID Connect (OIDC)

OIDC extends OAuth 2.0 by adding authentication capabilities via ID tokens.

**Why It Matters:**
- OAuth 2.0 does not define how to authenticate users
- OIDC enables federated SSO and standardized user information

**How It Works:**
- Uses OAuth 2.0 flows (Authorization Code Flow recommended)
- Returns both access and ID tokens
- ID tokens are JWTs with identity claims (email, name, etc.)

**Risks and Limitations:**
- ID tokens can be intercepted and misused if not validated
- Logout/session revocation is not always standard
- No default support for token binding to IP or client

**Best Practices:**
- Validate ID token signature, audience, issuer, and expiration
- Use short-lived tokens and secure refresh flows
- Log all token issuance and access patterns

---

## Lab Overview

This lab simulates a secure fintech API protected by Keycloak using OAuth 2.0 and OIDC.

### Use Case

Modern microservices require:
- Centralized authentication (via Keycloak)
- API-level authorization using JWT access tokens
- Trust-based delegation via OAuth and OIDC

### Solution Steps

- Deploy Keycloak and a Flask API via Docker Compose
- Auto-configure a realm, client, and user in Keycloak
- Retrieve and test a JWT token using the password grant
- Access a protected endpoint using a Bearer token

---

## Architecture Diagram

```
  +------------+      OAuth Login      +-------------+
  |   Browser  |  ------------------>  |  Keycloak   |
  +------------+                      +-------------+
        |                                     |
        |  Access Token (JWT)                 |
        | <-------------------------          |
        |                            \       |
        |                              \     |
        |        Protected API Call      \   |
        +------------------------------->+-------------+
                                        |   Flask App   |
                                        +---------------+
```

---

## What You Will Do in This Lab

1. Run Keycloak and Flask API in containers
2. Create a new realm, client, and test user
3. Request an access token using username/password
4. Pass token to API and inspect decoded claims

---

## Key Files and Components

| File                | Purpose                                                  |
|---------------------|----------------------------------------------------------|
| `setup.sh`          | Automates environment startup and configuration          |
| `realm-config.json` | Keycloak config (realm, client, user)                    |
| `docker-compose.yml`| Defines Flask and Keycloak services                      |
| `app/`              | Flask API, Dockerfile, and dependencies                  |
| `Makefile`          | CLI interface for start/reset/logs commands              |

---

## What to Expect

- JWT access token printed to terminal
- Flask API output showing decoded token
- Errors if token is missing or malformed

**Example API Call:**

```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:15000
```

Response:
```json
{
  "message": "Welcome!",
  "user": {
    "email": "testuser@example.com",
    "preferred_username": "testuser",
    ...
  }
}
```

---

## Running the Lab

1. **Unzip and Navigate**
```bash
unzip IAM_Lab1_Complete_Fixed.zip
cd IAM_Lab1_Fixed
```

2. **Start Lab**
```bash
make up
```

3. **Check Containers**
```bash
docker ps
```

4. **Re-test Access Token**
```bash
curl -X POST http://localhost:8080/realms/FintechApp/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=flask-client" \
  -d "client_secret=secret" \
  -d "username=testuser" \
  -d "password=password"
```

5. **Test Flask API**
```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:15000
```

6. **Tear Down**
```bash
make down
```

---

## Learning Objectives

By the end of this lab, you will be able to:
- Explain the OAuth 2.0 resource owner password grant flow
- Configure Keycloak for secure JWT issuance
- Validate tokens and secure microservices with identity-aware access
- Understand real-world IAM risks and mitigation techniques

