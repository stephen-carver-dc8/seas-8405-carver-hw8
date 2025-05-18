# Lab 1 – Mini-Enterprise IAM Stack

This lab demonstrates how to provision an OpenLDAP directory, federate it into Keycloak for SSO, and expose a protected intranet application—all via `localhost`.

## Prerequisites

- Docker & Docker Compose (`docker-compose` on Linux, `docker compose` on macOS)

## Setup

1. Start the stack:
   ```bash
   make up
   ```

2. Verify Keycloak is running:
   ```bash
   docker ps | grep keycloak
   curl -sf http://localhost:8080/realms/master
   ```

   3. Manually add the CentralIAM realm and LDAP provider:
      ```bash
      KC=$(docker ps -qf "ancestor=quay.io/keycloak/keycloak:24.0")

      # Login kcadm
      docker exec -i $KC /opt/keycloak/bin/kcadm.sh config credentials      --server http://localhost:8080 --realm master --user admin --password admin

      # Create realm
      docker exec -i $KC /opt/keycloak/bin/kcadm.sh create realms      -s realm=CentralIAM -s enabled=true || true

      # Configure LDAP provider
      docker exec -i $KC /opt/keycloak/bin/kcadm.sh create components -r CentralIAM \
  -s name=ldap \
  -s providerId=ldap \
  -s providerType=org.keycloak.storage.UserStorageProvider \
  -s parentId=CentralIAM \
  -s 'config.editMode=["READ_ONLY"]' \
  -s 'config.enabled=["true"]' \
  -s 'config.vendor=["other"]' \
  -s 'config.connectionUrl=["ldap://ldap:389"]' \
  -s 'config.usersDn=["ou=People,dc=example,dc=com"]' \
  -s 'config.authType=["simple"]' \
  -s 'config.bindDn=["cn=admin,dc=example,dc=com"]' \
  -s 'config.bindCredential=["adminpw"]' \
  -s 'config.userObjectClasses=["inetOrgPerson"]' \
  -s 'config.searchScope=["1"]' \
  -s 'config.usernameLDAPAttribute=["uid"]' \
  -s 'config.rdnLDAPAttribute=["uid"]' \
  -s 'config.uuidLDAPAttribute=["entryUUID"]' \
  -s 'config.pagination=["true"]' \
  -s 'config.trustEmail=["true"]' \
  -s 'config.importEnabled=["true"]'
   ```

4. Test DNS inside intranet container:
   ```bash
   docker exec -it $(docker ps -qf "ancestor=1-intranet")      ping -c 3 host.docker.internal
   ```

5. Open the intranet app in your browser:
   ```
   http://localhost:3000
   ```

## Cleanup

```bash
make down
```
