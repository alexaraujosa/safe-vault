# Communication Plan

The communication between the Client and Server solutions is established via TCP sockets.
All transmitted data flows through structured packets with a common header and a corresponding payload.  

These packets encapsulate JSON objects serialized in binary using the BSON module.
To ensure data confidentiality, the entire packet is encrypted.  

Upon establishing a connection, the client shares a certificate which is validated by the server.
This certificate allows the server to authenticate the client.  
The server answers with a packet containing its public key, used to encrypt the client packets.  

Each packet header includes the following fields:

- version: Specifies the protocol version, used to control the communication compatibility between the two solutions.
- type: Identifies the meaning of the payload, guiding its correct interpretation.

# Testing the communication

In order to test the communication between the server and a client:
1. Generate a CA with: `python3 server/certutil.py genca --out-dir certs`
2. Generate the Server Keystore with: `python3 server/certutil.py genstore --out-dir certs --name 'SSI Vault Server' --id 'VAULT_SERVER' --ca-cert=certs/VAULT_CA.crt --ca-key=certs/VAULT_CA.pem`
3. Generate a Client Keystore with: `python3 server/certutil.py genstore --out-dir certs --name 'User 1' --id 'VAULT_CLI1' --ca-cert=certs/VAULT_CA.crt --ca-key=certs/VAULT_CA.pem`
4. Start the server with: `python3 -m server.main --cert certs/VAULT_CA.crt --keystore certs/VAULT_SERVER.p12`
5. Run the client with `python3 -m client.main --cert certs/VAULT_CA.crt --keystore certs/VAULT_CLI1.p12`

Additionally, testing certificates where left on the `test` folder.
- `VAULT_CA.crt` is the certificate of the CA.
- `VAULT_CA.pem` is the private key of the CA.
- `VAULT_CLI4.p12` is the keystore of a valid client.
- `VAULT_CLI5.p12` is the keystore of a client that expired on 22/04/2025.
- `VAULT_SERVER.p12` is the server's keystore.
- `VAULT_SERVER2.p12` is a keystore for a "fake server". Used to test whether the client will reject a wrong connection.

# Commands

### add 

Client Packet Payload:
- file_name
- file_content

1. Client sends the packet to the server.
2. Server answers with a status code (success/failure).

### list

Client Packet Payload:
- (Optional) user_id / group_id

1. Client sends the packet to the server.
2. Server answers with a dictionary (file_name : permissions).
2.1. Server answers with the failure status code.

### share

First Client Packet Payload:
- file_id
- user_id
- permissions

Second Client Packet Payload:
- symmetric key: Encrypted with the user_id public key

1. Client sends the packet to the server.
2. Server answers with the file encrypted symmetric key and the user_id public key.
2.1. Server answers with failure status code.
3. Client sends a new packet to the server.
4. Server answers with a status code (success/failure).

### delete

Client Packet Payload:
- file_id

1. Client sends the packet to the server.
2. Server answers with a status code (success/failure).

### replace

First Client Packet Payload:
- file_id

Second Client Packet payload:
- new_content: Encrypted with the symmetric key

1. Client sends the packet to the server.
2. Server answers with the encrypted symmetric key.
2.1. Server answers with the failure status code.
3. Client sends a new packet to the server.
4. Server answers with a status code (success/failure).

### details

Client Packet Payload:
- file_id

1. Client sends the packet to the server.
2. Server answers with the metadata.
2.1. Server answers with the failure status code.

### revoke

Client Packet Payload:
- file_id
- user_id

1. Client sends the packet to the server.
2. Server answers with a status code (success/failure).

### read

Client Packet Payload:
- file_id

1. Client sends the packet to the server.
2. Server answers with the content.
2.1. Server answers with the failure status code.

### group create

Client Packet Payload:
- group_name

1. Client sends the packet to the server.
2. Server answers with a status code (success/failure).

### group delete

Client Packet Payload:
- group_id

1. Client sends the packet to the server.
2. Server answers with a status code (success/failure).

### group add-user

Client Packet Payload:
- group_id
- user_id
- permissions

1. Client sends the packet to the server.
2. Server answers with a status code (success/failure).

### group delete-user

Client Packet Payload:
- group_id
- user_id

1. Client sends the packet to the server.
2. Server answers with a status code (success/failure).

### group list

Client Packet Payload:
- group_id

1. Client sends the packet to the server.
2. Server answers with the group list.
2.1. Server answers with the failure status code.

### group add

Client Packet Payload:
- group_id
- file_name
- file_content

1. Client sends the packet to the server.
2. Server answers with a status code.