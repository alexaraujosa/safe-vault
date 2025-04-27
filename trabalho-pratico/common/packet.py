from bson   import BSON
from enum   import Enum
from typing import Any

PACKET_VERSION = 1

# TODO add replace, details, revoke, read, etc
class CommandType(Enum):
    ADD_REQUEST     = 0,
    ADD_RESPONSE    = 1,
    LIST_REQUEST    = 2,
    LIST_RESPONSE   = 3,
    SHARE_REQUEST   = 4,
    SHARE_RESPONSE  = 5,
    DELETE_REQUEST  = 6,
    DELETE_RESPONSE = 7,
    REPLACE_REQUEST = 8,
    REPLACE_RESPONSE = 9,
    REVOKE_REQUEST = 10,
    REVOKE_RESPONSE = 11,
    READ_REQUEST = 12,
    READ_RESPONSE = 13,
    GROUP_CREATE_REQUEST = 14,
    GROUP_DELETE_REQUEST = 15,
    GROUP_ADD_USER_REQUEST = 16,
    GROUP_DELETE_USER_REQUEST = 17,
    GROUP_LIST_REQUEST = 18,
    GROUP_ADD_REQUEST = 19,
    EXIT_REQUEST = 20



def create_packet(type: int, payload: dict) -> bytes:
    return BSON.encode({
        "version": PACKET_VERSION,
        "type": type,
        "payload": payload
    })

def decode_packet(packet: bytes) -> dict[str, Any]:
    dPacket = BSON.decode(packet)

    # Verify packet structure
    for key in ["version", "type", "payload"]:
        if dPacket.get(key) is None:
            raise ValueError(f"Malformed packet detected! Missing key '{key}'.")

    # Verify packet version
    if dPacket.get("version") != PACKET_VERSION:
        raise ValueError(f"Invalid packet version. Expected '{PACKET_VERSION}', got '{dPacket.get("version")}'.")
    
    # Verify command type
    try:
        CommandType(dPacket.get("type"))
    except ValueError:
        raise ValueError(f"Invalid packet command type. Got: {dPacket.get("type")}")
    
    return dPacket