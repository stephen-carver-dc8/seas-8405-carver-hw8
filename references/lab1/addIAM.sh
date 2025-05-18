KC=$(docker ps -qf "ancestor=quay.io/keycloak/keycloak:24.0")
# Login kcadm
docker exec -i $KC /opt/keycloak/bin/kcadm.sh config credentials      --server http://localhost:8080 --realm master --user admin --password admin
# Create realm
#docker exec -i $KC /opt/keycloak/bin/kcadm.sh create realms      -s realm=CentralIAM -s enabled=true || true
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
