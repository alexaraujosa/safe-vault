#!/bin/bash

# Generates the server CA certificate, server signed certificate, PKCS12 keystore,
# and client signed certificates and PKCS12 keystores using the certutil.py utility.
# For testing purposes, the script also generates:
# - A client PKCS12 with an invalid CA certificate (userInvalidCA)
# - A client PKCS12 with outdated validity dates (userOutdated)

# Run this script from the "trabalho-pratico" directory.
if [ "$(basename "$PWD")" != "trabalho-pratico" ]; then
    echo "Run this script from the root of the repository."
    exit 1
fi

# Define the N clients usernames
CLIENTS=(user1 user2 user3)

# Define certificates and keystores directories
CERTS_DIR="assets/certs"
KEYSTORES_DIR="assets/keystores"

# Create the directories for the certificates and keystores
mkdir -p $CERTS_DIR
mkdir -p $KEYSTORES_DIR

# Generate the server CA certificate (self-signed)
python3 server/certutil.py genca \
    --out-dir $CERTS_DIR

# Generate the server signed certificate and PKCS12 keystore
python3 server/certutil.py genstore \
    --out-dir $KEYSTORES_DIR \
    --common-name 'SSI Vault Server' \
    --id 'VAULT_SERVER' \
    --ca-cert=$CERTS_DIR/VAULT_CA.crt \
    --ca-key=$CERTS_DIR/VAULT_CA.pem

# Generate the clients signed certificates and PKCS12 keystores
for CLIENT in "${CLIENTS[@]}"; do
    python3 server/certutil.py genstore \
        --out-dir $KEYSTORES_DIR \
        --common-name "SSI Vault Client" \
        --id "$CLIENT" \
        --ca-cert=$CERTS_DIR/VAULT_CA.crt \
        --ca-key=$CERTS_DIR/VAULT_CA.pem
done

# Generate the invalid server CA certificate (for testing)
python3 server/certutil.py genca \
    --out-dir $CERTS_DIR \
    --id 'INVALID_VAULT_CA'

# Generate the invalid client PKCS12 keystore (for testing)
python3 server/certutil.py genstore \
    --out-dir $KEYSTORES_DIR \
    --common-name 'SSI Vault Client' \
    --id 'userInvalidCA' \
    --ca-cert=$CERTS_DIR/INVALID_VAULT_CA.crt \
    --ca-key=$CERTS_DIR/INVALID_VAULT_CA.pem

# Generate the outdated client PKCS12 keystore (for testing)
python3 server/certutil.py genstore \
    --out-dir $KEYSTORES_DIR \
    --common-name 'SSI Vault Client' \
    --id 'userOutdated' \
    --ca-cert=$CERTS_DIR/VAULT_CA.crt \
    --ca-key=$CERTS_DIR/VAULT_CA.pem \
    --not-valid-before '01/01/2024' \
    --not-valid-after '01/01/2025'
