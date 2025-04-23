# Testing the communication

In order to test the communication between the server and a client:
1. Generate a CA with: `./certutil.sh genca --out-dir certs`
2. Generate the Server Keystore with: `./certutil.sh genstore --out-dir certs --name 'SSI Vault Server' --id 'VAULT_SERVER' --ca-cert=certs/VAULT_CA.crt --ca-key=certs/VAULT_CA.pem`
3. Generate a Client Keystore with: `./certutil.sh genstore --out-dir certs --name 'User 4' --id 'VAULT_CLI4' --ca-cert=certs/VAULT_CA.crt --ca-key=certs/VAULT_CA.pem`
4. Start the server with: `./runServer.sh certs`
5. Run the client with `./runClient.sh test 4`

Additionally, I've left my testing certificates on the directory `test`.
- `VAULT_CA.crt` is the certificate of the CA.
- `VAULT_CA.pem` is the private key of the CA.
- `VAULT_CLI4.p12` is the keystore of a valid client.
- `VAULT_CLI5.p12` is the keystore of a client that expired on 22/04/2025.
- `VAULT_SERVER.p12` is the server's keystore.
- `VAULT_SERVER2.p12` is a keystore for a "fake server". Used to test whether the client will reject a wrong connection.

In order to test with the fake server, directly modify the `runSerfer.sh` script.