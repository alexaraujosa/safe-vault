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

## Commands

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