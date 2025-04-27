from common.validation import validate_params
from bson import BSON
from enum import Enum

PACKET_VERSION = 1


class CommandType(Enum):
    ADD_REQUEST     = 0,
    ADD_RESPONSE    = 1,
    LIST_REQUEST    = 2,
    LIST_RESPONSE   = 3,
    SHARE_REQUEST   = 4,
    SHARE_RESPONSE  = 5,
    DELETE_REQUEST  = 6,
    DELETE_RESPONSE = 7


def group_commands_usage():  # TODO moderator commands
    return """
Group commands usage:
    group create <group-name>
    group delete <group-id>
    group add-user <group-id> <user-id> <permissions>
    group delete-user <group-id> <user-id>
    group list
    group add <group-id> <file-path>
"""


def commands_usage():
    return f"""
Client commands usage:
    add <file-path>
    list [-u user_id | -g group_id]
    share <file-id> <user-id> <permissions>
    delete <file-id>
    replace <file-id> <file-path>
    details <file-id>
    revoke <file-id> <user-id>
    read <file-id>
{group_commands_usage()}
"""


def usage():  # TODO logs commands
    return f"""
{commands_usage()}
Logs command usage:
    TODO
Other commands:
    exit
"""


def create_packet(type: int, payload: dict) -> bytes:
    return BSON.encode({
        "version": PACKET_VERSION,
        "type": type,
        "payload": payload
    })


def validate_command(args: list) -> None:
    if not args or len(args) == 0:
        raise ValueError(f"Invalid arguments list: '{args}'")

    command = args[0]
    match command:
        case "add":
            if len(args) != 2:
                raise ValueError("Invalid arguments.\n"
                                 "Usage: add <file-path>")
            validate_params(file_path=args[1])

        case "list":
            if len(args) != 1 or len(args) != 3:
                raise ValueError("Invalid arguments.\n"
                                 "Usage: list [-u user_id | -g group_id]")

            if len(args) == 3:
                if args[1] not in ["-u", "-g"]:
                    raise ValueError("Invalid flag.\n"
                                     "Usage: list [-u user_id | -g group_id]")
                if args[1] == "-u":
                    validate_params(user_id=args[2])
                else:
                    validate_params(group_id=args[2])

        case "share":
            if len(args) != 4:
                raise ValueError("Invalid arguments.\n"
                                 "Usage: share <file-id> <user-id> <permissions>")
            validate_params(
                file_id=args[1],
                user_id=args[2],
                permissions=args[3]
            )

        case "delete":
            if len(args) != 2:
                raise ValueError("Invalid arguments.\n"
                                 "Usage: delete <file-id>")
            validate_params(file_id=args[1])

        case "replace":
            if len(args) != 3:
                raise ValueError("Invalid arguments.\n"
                                 "Usage: replace <file-id> <file-path>")
            validate_params(
                file_id=(file_id := args[1]),  # TODO use this syntax
                file_path=args[2]
            )

        case "details":
            if len(args) != 2:
                raise ValueError("Invalid arguments.\n"
                                 "Usage: details <file-id>")
            validate_params(file_id=args[1])

        case "revoke":
            if len(args) != 3:
                raise ValueError("Invalid arguments.\n"
                                 "Usage: revoke <file-id> <user-id>")
            validate_params(
                file_id=args[1],
                user_id=args[2]
            )

        case "read":
            if len(args) != 2:
                raise ValueError(f"Invalid arguments. Usage: read <file-id>")
            validate_params(
                file_id=args[1]
            )

        case "group":
            if len(args) < 2:
                raise ValueError(f"Invalid command '{command}'")
            group_command = args[1]
            match group_command:
                case "create":
                    if len(args) != 3:
                        raise ValueError(f"Invalid arguments. Usage: group create <group-name>")
                    validate_params(group_id=args[2])

                case "delete":
                    if len(args) != 3:
                        raise ValueError(f"Invalid arguments. Usage: group delete <group-id>")
                    validate_params(group_id=args[2])

                case "add-user":
                    if len(args) != 5:
                        raise ValueError(f"Invalid arguments. Usage: group add-user <group-id> <user-id> <permissions>")
                    validate_params(
                        group_id=args[2],
                        user_id=args[3],
                        permissions=args[4]
                    )

                case "delete-user":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments. Usage: group delete-user <group-id> <user-id>")
                    validate_params(
                        group_id=args[2],
                        user_id=args[3]
                    )

                case "list":
                    if len(args) != 2:
                        raise ValueError(f"Invalid arguments. Usage: group list")

                case "add":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments. Usage: group add <group-id> <file-path>")
                    validate_params(
                        group_id=args[2],
                        file_path=args[3]
                    )

        case _:
            raise ValueError(f"Invalid command '{command}'")


def process_command(client_socket, server_socket, args: list) -> None:
    if not args or len(args) == 0:
        raise ValueError(f"Invalid arguments list: '{args}'")
    command = args[0]

    match command:
        case "add":
            # TODO Retrieve filename from the path (args[1])
            with open(args[1], "rb") as file:
                content = file.read()
            # TODO Encrypt content
        case "list":
            pass
        case "share":
            pass
        case "delete":
            return create_packet(
                CommandType.DELETE_REQUEST.value,
                {
                    "file_id": args[1]
                }
            )
        case "replace":
            with open(args[2], "rb") as file:
                new_content = file.read()
            # TODO Encrypt new content
        case "details":
            pass
        case "revoke":
            pass
        case "read":
            pass
        case "group":
            group_command = args[1]
            match group_command:
                case "create":
                    pass
                case "delete":
                    pass
                case "add-user":
                    pass
                case "delete-user":
                    pass
                case "delete-user":
                    pass
                case "list":
                    pass
                case "add":
                    with open(args[3], "rb") as file:
                        content = file.read()
                    # TODO Encrypt content
                case _:
                    raise ValueError(f"Invalid group command: '{group_command}'\n"
                                     f"{group_commands_usage()}")
        case _:
            raise ValueError(f"Invalid command: '{command}'\n"
                             f"{usage()}")
