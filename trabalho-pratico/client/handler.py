import client.usage as usage
from common.validation import validate_params

from bson import BSON
from enum import Enum

# TODO move this variable to common
PACKET_VERSION = 1


# TODO move this class to common
# TODO add replace, details, revoke, read, etc
class CommandType(Enum):
    ADD_REQUEST     = 0,
    ADD_RESPONSE    = 1,
    LIST_REQUEST    = 2,
    LIST_RESPONSE   = 3,
    SHARE_REQUEST   = 4,
    SHARE_RESPONSE  = 5,
    DELETE_REQUEST  = 6,
    DELETE_RESPONSE = 7


# TODO move this function to common
def create_packet(type: int, payload: dict) -> bytes:
    return BSON.encode({
        "version": PACKET_VERSION,
        "type": type,
        "payload": payload
    })


def process_command(client_socket, server_socket, args: list) -> None:
    if not args or len(args) == 0:
        # INFO this exception should never be raised
        raise ValueError(f"No command provided.\n{usage._full}")

    command = args[0]
    match command:
        case "add":
            if len(args) != 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._add}")
            validate_params(file_path=(file_path := args[1]))

            # TODO Retrieve filename from the file_path (use basename)
            # TODO use try/except to handle file not found
            with open(file_path, "rb") as file:
                content = file.read()

            # TODO Encrypt content

            # TODO Create, encrypt and send packet
        # TODO 2 matches for list command maybe (clean)
        case "list":
            packet = None
            if len(args) == 1:
                packet = create_packet(CommandType.LIST_REQUEST.value, {})
            elif len(args) == 3:
                match args[1]:
                    case "-u":
                        packet = create_packet(CommandType.LIST_REQUEST.value,
                                               {"user_id": args[2]})
                    case "-g":
                        packet = create_packet(CommandType.LIST_REQUEST.value,
                                               {"group_id": args[2]})
                    case _:
                        raise ValueError(f"Invalid flag.\nUsage: {usage._list}")
            else:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._list}")

            # TODO Encrypt and send packet
            print(packet)
        case "share":
            if len(args) != 4:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._share}")
            validate_params(file_id=(file_id := args[1]),
                            user_id=(user_id := args[2]),
                            permissions=(permissions := args[3]))

            packet = create_packet(CommandType.SHARE_REQUEST.value,
                                   {"file_id": file_id,
                                    "user_id": user_id,
                                    "permissions": permissions})
            # TODO Request user public key from server
            # TODO Encrypt and send packet
            print(packet)
        case "delete":
            if len(args) != 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._delete}")
            validate_params(file_id=(file_id := args[1]))

            packet = create_packet(CommandType.DELETE_REQUEST.value,
                                   {"file_id": file_id})
        case "replace":
            if len(args) != 3:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._replace}")
            validate_params(file_id=(file_id := args[1]),
                            file_path=(file_path := args[2]))

            # TODO use try/except to handle file not found
            with open(file_path, "rb") as file:
                new_content = file.read()

            # TODO Encrypt new content
        case "details":
            if len(args) != 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._details}")
            validate_params(file_id=(file_id := args[1]))

            # TODO details
        case "revoke":
            if len(args) != 3:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._revoke}")
            validate_params(file_id=(file_id := args[1]),
                            user_id=(user_id := args[2]))

            # TODO revoke
        case "read":
            if len(args) != 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._read}")
            validate_params(file_id=(file_id := args[1]))

            # TODO read
        case "group":
            group_command = args[1]
            match group_command:
                case "create":
                    if len(args) != 3:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_create}")
                    validate_params(group_id=(group_id := args[2]))

                    # TODO Create group (server can return failure if it already exists)
                case "delete":
                    if len(args) != 3:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_delete}")
                    validate_params(group_id=(group_id := args[2]))

                    # TODO Delete group (server can return failure if it doesn't exist)
                case "add-user":
                    if len(args) != 5:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_add_user}")
                    validate_params(group_id=(group_id := args[2]),
                                    user_id=(user_id := args[3]),
                                    permissions=(permissions := args[4]))

                    # TODO add user
                case "delete-user":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_delete_user}")
                    validate_params(group_id=(group_id := args[2]),
                                    user_id=(user_id := args[3]))

                    # TODO delete user
                case "list":
                    if len(args) != 2:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_list}")

                    # TODO list groups
                case "add":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_add}")
                    validate_params(group_id=(group_id := args[2]),
                                    file_path=(file_path := args[3]))

                    # TODO use try/except to handle file not found
                    with open(file_path, "rb") as file:
                        content = file.read()

                    # TODO Retrieve filename from the file_path (use basename)

                    # TODO Encrypt content
                case _:
                    raise ValueError(f"Invalid command: group '{group_command}'\n"
                                     f"{usage._group}")
        case _:
            raise ValueError(f"Invalid command: '{command}'\n{usage._full}")
