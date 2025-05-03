# Plano de Encriptação de Ficheiros

**TODO** adicionar nota sobre a reencriptação de chaves e conteúdos em revogações,
explicar o processo em diferentes casos, e o porquê de não o termos feito
(ACL garante + eficiência de revogação). num ambiente de produção deve-se ponderar
esta reencriptação.

## 1. Key Management

### Client-side

Each client will use their private key (from their PKCS12 keystore) for:

- Digital signatures (authenticity)
- Decryption of files symmetric keys they have access to

### Server-side

The server will maintain:

- Server Credentials (PKCS12 keystore)
- A public key for each client for verifying signatures and wrapping symmetric keys
- Encrypted file storage with metadata in the ACL JSON

<div style="page-break-after: always;"></div>

## 2. File Encryption Scheme

Solution: **Hybrid encryption scheme**

### For Personal Vault Files

When a user adds a file to their personal vault, the following steps will be taken:

1. Client generates a random symmetric key (AES) for the file.
2. Client encrypts the file with the symmetric key generated in step 1.
3. Client encrypts the symmetric key with their public key.
4. Client signs the encrypted file.
5. Client sends the signed contents to the server:
    - Encrypted file
    - Encrypted symmetric key
    - Metadata
        - User ID (owner)
        - filename
        - etc (file size, ...)
6. Server stores the encrypted file and file's metadata in the JSON file.

### For Shared Files

When a user shares a file with another user, the following steps will be taken:

1. Owner retrieves the file symmetric key from the server.
2. Owner decrypts the symmetric key with their private key.
3. Owner encrypts the symmetric key with the recipient's public key.
4. Owner sends the signed contents to the server:
    - File ID
    - Symmetric key encrypted with recipient's public key
5. Server stores the encrypted symmetric key in the JSON file for the recipient.

<div style="page-break-after: always;"></div>

### For Group Files

1. Similar process to shared files, but the owner will encrypt the symmetric key
   with the public keys of all group members.
2. Server will store the encrypted symmetric key in the JSON file for each group member.

#### Problem with this approach

The original plan of encrypting the file key for each member individually creates:

- **Scalability Issues**: Storage grows exponentially (N files * M users)
- **Management Complexity**: Adding/removing users requires re-encrypting for all members
- **Security Risks**: No efficient way to revoke access (old copies remain decryptable)

#### Hierarchical Key Management solution

1. Group Key Generation:
    - Owner generates a unique symmetric key for the group. (master key)
    - This key is used to encrypt all files in the group
2. Key Distribution:
    - Owner encrypts the group key with each member's public key.
    - Each member can decrypt the group key with their private key.
3. File Encryption:
    - Upload: Encrypt once with group master key
    - Download: Member decrypts the group key with their private key,
        then decrypts the file with the group key.
4. Membership Changes:

 Action       | Process
--------------|---------
Add Member    | 1. Encrypt the group key with the new member's public key<br> 2. Send the encrypted group key to the new member
Remove Member | 1. Generate new group master key<br> 2. Re-encrypt all group files<br> 3 Update keys for remaining members

<div style="page-break-after: always;"></div>

## 3. Data Flow

### File Upload

1. Client reads the plaintext file.
2. Generates a random symmetric key (AES) storing it locally.
3. Encrypts the file with the symmetric key.
4. Encrypts the symmetric key with the his public key.
5. Signs encrypted file + metadata with owner's private key
6. Sends to server

### File Download

1. Server sends encrypted file + encrypted symmetric key to authorized client.
2. Client verifies the signature.
3. Client decrypts the AES symmetric key with their private key.
4. Client decrypts the file with the symmetric key.

## 5. Security Guarantees

### Confidentiality

- Server never sees plaintext files or symmetric keys
- Only users with proper permissions can decrypt files

### Integrity

- Digital signatures ensure files aren't modified in transit
- HMAC can be used for additional integrity checks

### Authenticity

- All operations require valid certificates
- Digital signatures prove file origin

<div style="page-break-after: always;"></div>

## 6. Considerations

### Performance

- Symmetric encryption for file contents (fast)
- Asymmetric only for key exchange (small payloads)

### Error Handling

- Handle decryption errors gracefully
- Verify signatures before any operation
- Log errors for auditing

# Implementation

Once the encryption plan is approved.
The following steps will be taken in regard to the JSON file:

- Store client public keys when creating a new user in the JSON file.
- Add encrypted_key field to the JSON file for each file (owned/shared).
- (...)
