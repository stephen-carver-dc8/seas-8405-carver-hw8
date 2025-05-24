#!/bin/bash
/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin

# Add realm, client, user (omit for brevity, mirror lab logic)
