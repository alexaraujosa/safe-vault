#/bin/bash

# DIR=${1:-"assets/projCA"}
DIR=${1:-"test"}
CLIENT=${2:-1}
python3 -m ssiproject.client.client --cert $DIR/VAULT_CA.crt --keystore $DIR/VAULT_CLI$CLIENT.p12