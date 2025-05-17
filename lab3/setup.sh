#!/usr/bin/env bash
set -eo pipefail

REALM="FintechApp"
KEYCLOAK_URL="http://localhost:8080"
SAML_DIR="./app/saml"

########################################
# A) Generate SP cert/key if missing
########################################
mkdir -p "$SAML_DIR"
if [[ ! -f "$SAML_DIR/key.pem" || ! -f "$SAML_DIR/cert.pem" ]]; then
  echo "[*] Generating self-signed SP certificate…"
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$SAML_DIR/key.pem" \
    -x509 -days 365 \
    -out "$SAML_DIR/cert.pem" \
    -subj "/C=US/ST=Lab/L=DemoOrg/O=DemoOrg/CN=localhost"
fi

########################################
# B) Start Keycloak & LDAP
########################################
echo "[*] Starting Keycloak & LDAP…"
docker compose up -d --build keycloak ldap

########################################
# C) Wait for Keycloak to be ready
########################################
for i in {30..1}; do
  if curl -sf "$KEYCLOAK_URL"; then
    echo "[*] Keycloak is up."
    break
  fi
  echo "  still waiting for Keycloak… ($i)"
  sleep 2
done
curl -sf "$KEYCLOAK_URL" >/dev/null || {
  echo "[!] Keycloak never became ready. Exiting."
  exit 1
}

########################################
# D) Authenticate kcadm.sh
########################################
KC_CLI=$(docker ps --filter "ancestor=quay.io/keycloak/keycloak:latest" --format "{{.Names}}")
echo "[*] Logging into Keycloak CLI…"
docker exec "$KC_CLI" /opt/keycloak/bin/kcadm.sh config credentials \
  --server "$KEYCLOAK_URL" --realm master \
  --user admin --password admin123

########################################
# E) Delete & (re)create FintechApp realm
########################################
echo "[*] Deleting any existing realm '$REALM'…"
docker exec "$KC_CLI" /opt/keycloak/bin/kcadm.sh delete realms/$REALM || true

echo "[*] Creating realm '$REALM'…"
docker exec "$KC_CLI" /opt/keycloak/bin/kcadm.sh create realms \
  -s realm="$REALM" -s enabled=true

########################################
# F) Wait for IdP SAML metadata
########################################
IDP_META="$KEYCLOAK_URL/realms/$REALM/protocol/saml/descriptor"
echo "[*] Waiting for IdP SAML metadata…"
for i in {30..1}; do
  if curl -sf "$IDP_META"; then
    echo "[*] IdP metadata is now available."
    break
  fi
  echo "  still waiting for metadata… ($i)"
  sleep 2
done
curl -sf "$IDP_META" >/dev/null || {
  echo "[!] IdP metadata never appeared. Exiting."
  exit 1
}

########################################
# G) Extract X.509 cert from metadata
########################################
echo "[*] Extracting IdP certificate…"
IDP_CERT=$(curl -sf "$IDP_META" \
  | xmllint --xpath "string(//*[local-name()='X509Certificate'])" - \
  | tr -d '[:space:]')
if [[ -z "$IDP_CERT" ]]; then
  echo "[!] Failed to extract X509Certificate. Exiting."
  exit 1
fi

########################################
# H) Write python3-saml settings.json
########################################
echo "[*] Writing SP settings.json…"
SP_CERT=$(awk 'BEGIN{ORS="\\n"}1' "$SAML_DIR/cert.pem")
SP_KEY=$(awk 'BEGIN{ORS="\\n"}1' "$SAML_DIR/key.pem")

cat > "$SAML_DIR/settings.json" <<EOF
{
  "strict": false,
  "debug": true,
  "sp": {
    "entityId": "http://localhost:15001/sso/metadata",
    "assertionConsumerService": {
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      "url": "http://localhost:15001/sso/acs"
    },
    "singleLogoutService": {
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
      "url": "http://localhost:15001/sso/sls"
    },
    "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    "x509cert": "$SP_CERT",
    "privateKey": "$SP_KEY"
  },
  "idp": {
    "entityId": "$KEYCLOAK_URL/realms/$REALM",
    "singleSignOnService": {
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
      "url": "$KEYCLOAK_URL/realms/$REALM/protocol/saml"
    },
    "singleLogoutService": {
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
      "url": "$KEYCLOAK_URL/realms/$REALM/protocol/saml"
    },
    "x509cert": "$IDP_CERT"
  },
  "security": {
    "authnRequestsSigned": false,
    "logoutRequestSigned": false,
    "logoutResponseSigned": false,
    "signMetadata": false,
    "wantAssertionsSigned": false
  }
}
EOF

# mirror for top‐level saml/
cp "$SAML_DIR/settings.json" "./saml/settings.json"

########################################
# I) Start your Flask SP & run remaining steps
########################################
echo "[*] Starting Flask SP…"
docker compose up -d --build app

# …your LDAP federation & SAML‐client creation go here…

########################################
# I) Configure LDAP federation + sample user
########################################
echo "[*] Adding sample user to LDAP…"
cat > sample-user.ldif <<EOF
dn: uid=jdoe,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
uid: jdoe
userPassword: password
mail: jdoe@example.org
EOF

LDAP_C=$(docker ps --filter "ancestor=osixia/openldap:1.5.0" --format "{{.Names}}")
docker cp sample-user.ldif "$LDAP_C":/tmp/sample-user.ldif
docker exec "$LDAP_C" ldapadd -x -D "cn=admin,dc=example,dc=org" -w admin \
  -f /tmp/sample-user.ldif || true

echo "[*] Configuring LDAP provider in Keycloak…"
cat > ldap-config.json <<EOF
{
  "name":"ldap",
  "providerId":"ldap",
  "providerType":"org.keycloak.storage.UserStorageProvider",
  "config": {
    "editMode":["READ_ONLY"],"enabled":["true"],"vendor":["other"],
    "connectionUrl":["ldap://ldap:389"],"usersDn":["dc=example,dc=org"],
    "authType":["simple"],"bindDn":["cn=admin,dc=example,dc=org"],"bindCredential":["admin"],
    "userObjectClasses":["inetOrgPerson","organizationalPerson"],"searchScope":["1"],
    "usernameLDAPAttribute":["uid"],"rdnLDAPAttribute":["uid"],"uuidLDAPAttribute":["entryUUID"],
    "userEnabledAttribute":["userAccountControl"],"pagination":["true"],
    "syncRegistrations":["false"],"trustEmail":["true"],"importEnabled":["true"]
  }
}
EOF

if ! docker exec "$KC_CLI" /opt/keycloak/bin/kcadm.sh get components -r "$REALM" \
     | grep -q '"providerId":"ldap"'; then
  docker cp ldap-config.json "$KC_CLI":/tmp/ldap-config.json
  docker exec "$KC_CLI" /opt/keycloak/bin/kcadm.sh create components \
    -r "$REALM" -f /tmp/ldap-config.json
fi

########################################
# J) Create & configure the SAML client
########################################
echo "[*] Creating SAML client…"
cat > saml-client.json <<EOF
{
  "clientId":"http://localhost:15001/sso/metadata",
  "protocol":"saml",
  "enabled":true,
  "redirectUris":["http://localhost:15001/sso/acs"],
  "baseUrl":"http://localhost:15001",
  "rootUrl":"http://localhost:15001",
  "adminUrl":"http://localhost:15001",
  "attributes":{
    "saml_force_name_id_format":"true",
    "saml_name_id_format":"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    "saml.authnstatement":"true",
    "saml.assertion.signature":"false",
    "saml.encrypt":"false",
    "saml.multivalued.roles":"false",
    "saml.server.signature":"false",
    "saml.client.signature":"false"
  },
  "protocolMappers":[
    {
      "name":"username","protocol":"saml","protocolMapper":"saml-user-property-mapper",
      "consentRequired":false,
      "config":{
        "user.attribute":"username","friendly.name":"username",
        "attribute.name":"username","attribute.nameformat":"Basic"
      }
    },
    {
      "name":"email","protocol":"saml","protocolMapper":"saml-user-property-mapper",
      "consentRequired":false,
      "config":{
        "user.attribute":"email","friendly.name":"email",
        "attribute.name":"email","attribute.nameformat":"Basic"
      }
    }
  ]
}
EOF

if ! docker exec "$KC_CLI" /opt/keycloak/bin/kcadm.sh get clients -r "$REALM" \
     | jq -e '.[]|select(.clientId=="http://localhost:15001/sso/metadata")' >/dev/null; then
  docker cp saml-client.json "$KC_CLI":/tmp/saml-client.json
  docker exec "$KC_CLI" /opt/keycloak/bin/kcadm.sh create clients \
    -r "$REALM" -f /tmp/saml-client.json
fi

########################################
# K) Smoke-test
########################################
echo "[*] Verifying SP metadata…"
if curl -sSf http://localhost:15001/sso/metadata | grep -q "EntityDescriptor"; then
  echo "[✓] SP metadata is available."
else
  echo "[✗] SP metadata failed—check Flask logs."
  exit 1
fi

echo "[*] Verifying /sso/login redirect…"
if curl -sS --head -L http://localhost:15001/sso/login | grep -q "302"; then
  echo "[✓] /sso/login correctly redirects."
else
  echo "[✗] /sso/login did not redirect as expected."
  exit 1
fi

echo "[✓] Setup complete!"
echo "    • Metadata: http://localhost:15001/sso/metadata"
echo "    • Login URL: http://localhost:15001/sso/login"
