import client.usage as usage
from client.encryption import RSA, AES_GCM
from common.validation import validate_params
from common.packet import (
    CommandType,
    create_packet,
    decode_packet
)


def handle_boolean_response(response: dict) -> bool:
    """
    Handle boolean response from server.
    Returns True if the response is successful, False otherwise.
    Prints the message if present.

    INFO: Packet is already verified with decode_packet() so the payload exists.
    """
    message = response.get("payload").get("message")
    if message:
        print(message)

    return response.get("type") == CommandType.SUCCESS.value


def process_command(client_socket,  # TODO add type
                    server_socket,  # TODO add type
                    args: list,
                    client_private_key: bytes,
                    client_public_key: bytes):
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
        case "list", *rest:
            match rest:
                case []:  # list
                    packet = create_packet(CommandType.LIST_REQUEST.value, {})

                case ["-u", user_id]:  # list -u <user_id>
                    validate_params(user_id=user_id)
                    packet = create_packet(CommandType.LIST_REQUEST.value,
                                           {"user_id": user_id})

                case ["-g", group_id]:  # list -g <group_id>
                    validate_params(group_id=group_id)
                    packet = create_packet(CommandType.LIST_REQUEST.value,
                                           {"group_id": group_id})

                case _:
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
            if len(args) < 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._group}")

            group_command = args[1]
            match group_command:
                case "create":
                    if len(args) != 3:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_create}")
                    validate_params(group_id=(group_id := args[2]))

                    # Create master group key AES
                    group_key = AES_GCM.generate_key()

                    # Encrypt master group key with current user private key
                    group_key = RSA.encrypt(group_key, client_private_key)

                    # Send group creation request to server
                    packet = create_packet(CommandType.GROUP_CREATE_REQUEST.value,
                                           {"name": group_id,
                                            "key": str(group_key)})
                    server_socket.send(packet)

                    # Await server boolean response
                    response = decode_packet(server_socket.recv())
                    handle_boolean_response(response)

                case "delete":
                    if len(args) != 3:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_delete}")
                    validate_params(group_id=(group_id := args[2]))

                    # Send group deletion request to server
                    packet = create_packet(CommandType.GROUP_DELETE_REQUEST.value,
                                           {"group_id": group_id})
                    server_socket.send(packet)

                    # Await server boolean response
                    response = decode_packet(server_socket.recv())
                    handle_boolean_response(response)

                case "add-user":
                    if len(args) != 5:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_add_user}")
                    validate_params(group_id=(group_id := args[2]),
                                    user_id=(user_id := args[3]),
                                    permissions=(permissions := args[4]))

                    # TODO Request master group and user public keys from server (server can deny)
                    # TODO Decrypt the user public key with the current user private key
                    # TODO Encrypt the master group public key with the user public key
                    # TODO Send the encrypted master group public key to the server
                    # payload = {
                    #    "group_id": group_id,
                    #    "user_id": user_id,
                    #    "permissions": permissions,
                    #    "group_key": encrypted_group_key
                    # }
                case "delete-user":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_delete_user}")
                    validate_params(group_id=(group_id := args[2]),
                                    user_id=(user_id := args[3]))

                    # Send user group deletion request to server
                    packet = create_packet(CommandType.GROUP_DELETE_USER_REQUEST.value,
                                           {"group_id": group_id,
                                            "user_id": user_id})
                    server_socket.send(packet)

                    # Await server response (CONFIRM_REQUEST | SUCCESS | ERROR)
                    response = decode_packet(server_socket.recv())
                    if response.get("type") == CommandType.CONFIRM_REQUEST.value:
                        print(response.get("payload").get("message"))
                        confirm = input("Do you want to continue? [y/N] ")
                        if confirm.lower() == "y":
                            packet = create_packet(CommandType.GROUP_DELETE_USER_REQUEST.value,
                                                   {"group_id": group_id,
                                                    "user_id": user_id,
                                                    "confirm": True})
                            server_socket.send(packet)
                        else:
                            print("Operation cancelled.")

                    handle_boolean_response(response)

                case "list":
                    if len(args) != 2:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_list}")

                    # Send group list request to server
                    packet = create_packet(CommandType.GROUP_LIST_REQUEST.value,
                                           {"group_id": group_id})
                    server_socket.send(packet)

                    # Await server response (group_list | ERROR)
                    # TODO Server: add the group_list to the payload.message field
                    # this way no if statement is needed here
                    response = decode_packet(server_socket.recv())
                    print(response.get("payload").get("message"))

                case "add":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_add}")
                    validate_params(group_id=(group_id := args[2]),
                                    file_path=(file_path := args[3]))

                    # TODO use try/except to handle file not found
                    with open(file_path, "rb") as file:
                        content = file.read()

                    # TODO Retrieve file_:name from the file_path (use basename)
                    # TODO Ask server for group public key (server can deny, e.g. permissions, group not found)
                    # TODO Encrypt content with group public key
                    # TODO Send add file to group request to server (check for server response)
                case _:
                    raise ValueError(f"Invalid command: group '{group_command}'\n"
                                     f"{usage._group}")
        case _:
            raise ValueError(f"Invalid command: '{command}'\n{usage._full}")
