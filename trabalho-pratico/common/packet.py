from bson   import BSON
from enum   import Enum

PACKET_VERSION = 1


# TODO add replace, details, revoke, read, etc
# TODO remove some unessary responses
class CommandType(Enum):
    SUCCESS                   = 0
    ERROR                     = 1
    ADD_REQUEST               = 2
    ADD_RESPONSE              = 3
    LIST_REQUEST              = 4
    LIST_RESPONSE             = 5
    SHARE_REQUEST             = 6
    SHARE_RESPONSE            = 7
    DELETE_REQUEST            = 8
    DELETE_RESPONSE           = 9
    REPLACE_REQUEST           = 10
    REPLACE_RESPONSE          = 11
    REVOKE_REQUEST            = 12
    REVOKE_RESPONSE           = 13
    READ_REQUEST              = 14
    READ_RESPONSE             = 15
    GROUP_CREATE_REQUEST      = 16
    GROUP_DELETE_REQUEST      = 17
    GROUP_ADD_USER_REQUEST    = 18
    GROUP_DELETE_USER_REQUEST = 19
    GROUP_LIST_REQUEST        = 20
    GROUP_ADD_REQUEST         = 21
    EXIT_REQUEST              = 22
    NEED_CONFIRMATION         = 23
    CONFIRM                   = 24
    ABORT                     = 25

    DETAILS_REQUEST           = 26
    # DETAILS_RESPONSE          = 27


def create_packet(p_type: int, payload: dict) -> bytes:
    return BSON.encode({
        "version": PACKET_VERSION,
        "type": p_type,
        "payload": payload
    })


def create_success_packet(message: str = None) -> bytes:
    payload = {"message": message} if message else {}
    return create_packet(CommandType.SUCCESS.value, payload)


def create_error_packet(message: str) -> bytes:
    return create_packet(CommandType.ERROR.value, {"message": message})


def create_need_confirmation_packet(message: str) -> bytes:
    return create_packet(CommandType.NEED_CONFIRMATION.value, {"message": message})


def create_confirm_packet() -> bytes:
    return create_packet(CommandType.CONFIRM.value, {})


def create_abort_packet() -> bytes:
    return create_packet(CommandType.ABORT.value, {})


def decode_packet(packet_data: bytes) -> dict:
    packet = BSON.decode(packet_data)

    # Verify packet structure
    for key in ["version", "type", "payload"]:
        if packet.get(key) is None:
            raise ValueError(f"Malformed packet detected! Missing key '{key}'.")

    # Verify packet version
    if packet.get("version") != PACKET_VERSION:
        raise ValueError("Invalid packet version.\n"
                         f"Expected '{PACKET_VERSION}', got '{packet.get("version")}'.")

    # Verify command type
    try:
        CommandType(packet.get("type"))
    except ValueError:
        raise ValueError("Invalid packet command type.\n"
                         f"Got: {packet.get("type")}")

    return packet
