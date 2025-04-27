#/bin/bash

# DIR=${1:-"assets/projCA"}
DIR=${1:-"test"}
python3 -m ssiproject.server.server --cert $DIR/VAULT_CA.crt --keystore $DIR/VAULT_SERVER.p12
[[ $? -ne 0 ]] && exit;
echo END