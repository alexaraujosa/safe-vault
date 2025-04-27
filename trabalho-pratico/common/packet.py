from bson   import BSON
from enum   import Enum
from typing import Any

PACKET_VERSION = 1


# TODO add replace, details, revoke, read, etc
# TODO remove some unessary responses
class CommandType(Enum):
    SUCCESS                   = 0,
    ERROR                     = 1,
    ADD_REQUEST               = 2,
    ADD_RESPONSE              = 3,
    LIST_REQUEST              = 4,
    LIST_RESPONSE             = 5,
    SHARE_REQUEST             = 6,
    SHARE_RESPONSE            = 7,
    DELETE_REQUEST            = 8,
    DELETE_RESPONSE           = 9,
    REPLACE_REQUEST           = 10,
    REPLACE_RESPONSE          = 11,
    REVOKE_REQUEST            = 12,
    REVOKE_RESPONSE           = 13,
    READ_REQUEST              = 14,
    READ_RESPONSE             = 15,
    GROUP_CREATE_REQUEST      = 16,
    GROUP_DELETE_REQUEST      = 17,
    GROUP_ADD_USER_REQUEST    = 18,
    GROUP_DELETE_USER_REQUEST = 19,
    GROUP_LIST_REQUEST        = 20,
    GROUP_ADD_REQUEST         = 21,
    EXIT_REQUEST              = 22


def create_packet(type: int, payload: dict) -> bytes:
    return BSON.encode({
        "version": PACKET_VERSION,
        "type": type,
        "payload": payload
    })


def create_error_packet(message: str) -> bytes:
    return create_packet(CommandType.ERROR.value, {"message": message})


def create_success_packet(message: str) -> bytes:
    return create_packet(CommandType.SUCCESS.value, {"message": message})


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
