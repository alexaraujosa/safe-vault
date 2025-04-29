import ssl
import traceback
from io import BytesIO
from bson   import BSON
from enum   import Enum, auto

PACKET_VERSION = 1


# TODO remove some unnecessary responses
class CommandType(Enum):
    SUCCESS                   = auto()
    ERROR                     = auto()
    ADD_REQUEST               = auto()
    ADD_RESPONSE              = auto()
    LIST_REQUEST              = auto()
    LIST_RESPONSE             = auto()
    SHARE_REQUEST_VALIDATION  = auto()
    SHARE_RESPONSE_VALIDATION = auto()
    SHARE_REQUEST_WITH_KEY    = auto()
    DELETE_REQUEST            = auto()
    DELETE_RESPONSE           = auto()
    REPLACE_REQUEST_VALIDATION = auto()
    REPLACE_RESPONSE_VALIDATION = auto()
    REPLACE_REQUEST_WITH_CONTENT = auto()
    REVOKE_REQUEST            = auto()
    REVOKE_RESPONSE           = auto()
    READ_REQUEST              = auto()
    READ_RESPONSE             = auto()
    GROUP_CREATE_REQUEST      = auto()
    GROUP_DELETE_REQUEST      = auto()
    INIT_GROUP_ADD_USER_REQUEST = auto()
    INIT_GROUP_ADD_USER_RESPONSE = auto()
    GROUP_ADD_USER_REQUEST    = auto()
    GROUP_DELETE_USER_REQUEST = auto()
    GROUP_LIST_REQUEST        = auto()
    INIT_GROUP_ADD_REQUEST    = auto()
    INIT_GROUP_ADD_RESPONSE   = auto()
    GROUP_ADD_REQUEST         = auto()
    NEED_CONFIRMATION         = auto()
    CONFIRM                   = auto()
    ABORT                     = auto()

    DETAILS_REQUEST           = auto()
    DETAILS_RESPONSE          = auto()


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
                         f"Expected '{PACKET_VERSION}', got '{packet.get('version')}'.")

    # Verify command type
    try:
        CommandType(packet.get("type"))
    except ValueError:
        raise ValueError("Invalid packet command type.\n"
                         f"Got: {packet.get('type')}")

    return packet

def read_fully(conn: ssl.SSLSocket, debug = False):
    try:
        initFrag = conn.recv()

        if (debug): print("Initial Fragment:", len(initFrag))
        packet = BytesIO()
        packet.write(initFrag)
        
        totalLen = int.from_bytes(initFrag[0:4], byteorder="little", signed=True)
        accLen = len(initFrag)

        if (debug): print("TOTAL LENGTH:", totalLen)
        
        while (accLen < totalLen):
            if (debug): print("READ:", accLen, "/", totalLen, "\nTO READ:", totalLen - accLen)
            frag = conn.recv(totalLen - accLen) # Do not read the next packet by mistake
            if (debug): print("New Fragment:", len(frag))

            accLen += len(frag)
            packet.write(frag)
        
        if (debug): print("FINISHED READ:", accLen, "/", totalLen)

        packet.seek(0)
        return packet.read(totalLen)
    except ssl.SSLEOFError: # Connection died before receiving the full packet
        return None
    except Exception:
        if (debug):
            print(f"📧 Error reading packet.")
            traceback.print_exc()
            
        return None
