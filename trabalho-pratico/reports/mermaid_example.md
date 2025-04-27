# Secure Vault Communication Protocol

## Packet Structure
```mermaid
classDiagram
    class Packet {
        +header: Header
        +payload: binary
    }

    class Header {
        +version: int
        +type: str
        +timestamp: datetime
        +integrity_check: str?
    }
```

## Authentication Flow
```mermaid
sequenceDiagram
    participant Client
    participant Server

    Client->>Server: TCP Connection
    Client->>Server: Client Certificate
    Server-->>Client: Server Public Key (RSA)
    Note over Client,Server: Mutual TLS Handshake Complete
```

## File Sharing (`share` command)
```mermaid
sequenceDiagram
    participant Client
    participant Server

    Client->>Server: {"type": "share", "file_id": "123", "user_id": "bob", "permissions": "RW"}
    Server-->>Client: {"status": "need_key", "pubkey": "..."}
    Client->>Server: {"type": "key_exchange", "enc_key": "<AES_key_encrypted_with_bob's_pubkey>"}
    Server-->>Client: {"status": "success"}
```

## File Replacement (`replace` command)
```mermaid
sequenceDiagram
    participant Client
    participant Server

    Client->>Server: {"type": "replace", "file_id": "123"}
    alt File exists
        Server-->>Client: {"status": "need_content", "enc_key": "<AES_key_encrypted_with_client's_pubkey>"}
        Client->>Server: {"type": "content", "data": "<new_content_encrypted_with_AES>"}
        Server-->>Client: {"status": "success"}
    else File not found
        Server-->>Client: {"status": "error", "code": 404}
    end
```

## Group Management
```mermaid
flowchart TD
    A[Client] -->|group create| B(Server)
    B --> C{Valid?}
    C -->|Yes| D[Add to config]
    C -->|No| E[Return error]
    D --> F[Notify members]
```

## Error Handling States
```mermaid
stateDiagram-v2
    [*] --> Connected
    Connected --> Authenticated: Valid Certificate
    Authenticated --> Processing: Valid Command
    Processing --> Success: Operation Complete
    Processing --> Error: Invalid Request
    Error --> Processing: Retry
    Error --> [*]: Fatal Error
```

## Key Exchange Details
```mermaid
pie
    title Encryption Key Types
    "File Keys (AES-256)" : 70
    "User Keys (RSA-2048)" : 20
    "Group Keys (AES-256)" : 10
```

## Implementation Notes
1. **BSON Schema**:
```python
{
    "header": {
        "version": 1,
        "type": "command_name",
        "timestamp": "ISO8601"
    },
    "payload": "binary_encrypted_data"
}
```

2. **Status Codes**:
- `200`: Success
- `400`: Invalid request
- `403`: Permission denied
- `404`: Not found
- `500`: Server error
