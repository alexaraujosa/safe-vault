python3 -m ssiproject.server.server --cert assets/projCA/VAULT_CA.crt --keystore assets/projCA/VAULT_SERVER.p12
[[ $? -ne 0 ]] && exit
echo END