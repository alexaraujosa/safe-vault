import os
import socket
from ssl import SSLSocket
from bson import BSON
from cryptography.hazmat.primitives import serialization
import client.usage as usage
from client.encryption import RSA, AES_GCM
from client.tabulate   import tabulate
from common.validation import validate_params
from common.packet import (
    PacketType,
    create_packet,
    create_confirm_packet,
    create_abort_packet,
    receive_packet,
)


def print_logs(logs: list) -> None:
    print(tabulate(logs, headers="keys", tablefmt="rounded_outline"))


def read_file(file_path: str) -> bytes:
    """
    Read file content and return it as bytes.

    Any exception raised will be a ValueError with a message.
    """
    try:
        with open(file_path, "rb") as file:
            content = file.read()
    except FileNotFoundError:
        raise ValueError(f"File '{file_path}' not found.")
    except PermissionError:
        raise ValueError(f"Permission denied to read file '{file_path}'.")
    except IsADirectoryError:
        raise ValueError(f"File '{file_path}' is a directory.")
    except Exception as e:
        raise ValueError(f"Error reading file '{file_path}': {e}")

    return content


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

    return response.get("type") == PacketType.SUCCESS.value


def process_command(client_socket: socket,
                    server_socket: SSLSocket,
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
            file_path = args[1]

            filename = os.path.basename(file_path)
            content = read_file(file_path)

            # Create file master key with AES
            file_key = AES_GCM.generate_key()

            # Encrypt content with symmetric key
            enc_content = BSON.encode(AES_GCM.encrypt(content, file_key))

            # Encrypt file master key with client public key
            enc_file_key = RSA.encrypt(file_key, client_public_key)

            packet = create_packet(PacketType.ADD.value,
                                   {"content": enc_content,
                                    "key": enc_file_key,
                                    "size": len(content),
                                    "filename": filename})
            server_socket.send(packet)

            # Await server response
            response = receive_packet(server_socket)
            handle_boolean_response(response)

        case "list":
            rest = args[1:]
            match rest:
                case []:  # list
                    packet = create_packet(PacketType.LIST.value, {})

                case ["-o"]:  # list -o
                    packet = create_packet(PacketType.LIST.value,
                                           {"owner": True})

                case ["-u", user_id]:  # list -u <user_id>
                    validate_params(user_id=user_id)
                    packet = create_packet(PacketType.LIST.value,
                                           {"user_id": user_id})

                case ["-g", group_id]:  # list -g <group_id>
                    validate_params(group_id=group_id)
                    packet = create_packet(PacketType.LIST.value,
                                           {"group_id": group_id})

                case _:
                    raise ValueError(f"Invalid arguments.\nUsage: {usage._list}")

            server_socket.send(packet)

            # Await server response
            response = receive_packet(server_socket)
            payload = response.get("payload")
            if response.get("type") == PacketType.ERROR.value:
                print(payload.get("message"))
                return

            # Print the results
            if len(payload) == 0:
                print("You have no access to any files.")
                return

            first = True
            for k, v in payload.items():
                if not first:
                    print()

                match k:
                    case "owned_files":
                        if len(v) == 0:
                            print("You don't own any files.")
                            continue
                        print("Owned files:")
                        headers = ["File ID"]
                        table_data = [[file_id] for file_id in v]  # to ensure proper format
                    case "shared_files":
                        if len(v) == 0:
                            print("You don't have any files being shared with you.")
                            continue
                        print("Shared files:")
                        headers = ["File ID", "Permissions"]
                        table_data = v
                    case "group_files":
                        if len(v) == 0:
                            print("You don't have any files in groups you are a member of.")
                            continue
                        print("Group files:")
                        headers = ["File ID", "Permissions", "Group ID"]
                        table_data = v

                print(tabulate(table_data, headers=headers, tablefmt="rounded_outline"))
                first = False

        case "share":
            if len(args) != 4:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._share}")
            validate_params(file_id=(file_id := args[1]),
                            user_id=(user_id := args[2]),
                            permissions=(permissions := args[3]))

            packet = create_packet(PacketType.SHARE.value,
                                   {"file_id": file_id,
                                    "user_id": user_id,
                                    "permissions": permissions})
            server_socket.send(packet)

            # Await server response
            response = receive_packet(server_socket)
            payload  = response.get("payload")
            if response.get("type") == PacketType.ERROR.value:
                print(payload.get("message"))
                return

            user_pub_key_bytes = payload.get("public_key")
            user_pub_key = serialization.load_pem_public_key(user_pub_key_bytes)
            file_symmetric_key_enc = payload.get("file_symmetric_key")

            # Decrypt file symmetric key
            file_symmetric_key = RSA.decrypt(file_symmetric_key_enc, client_private_key)

            # Encrypt file symmetric key with share user public key
            share_user_file_symmetric_key_enc = RSA.encrypt(file_symmetric_key, user_pub_key)

            # Send share user file symmetric key to server
            packet_share = create_packet(PacketType.SHARE.value,
                                         {"key": share_user_file_symmetric_key_enc})
            server_socket.send(packet_share)

            # Await server response
            response = receive_packet(server_socket)
            handle_boolean_response(response)

        case "delete":
            if len(args) != 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._delete}")
            validate_params(file_id=(file_id := args[1]))

            packet = create_packet(PacketType.DELETE.value,
                                   {"file_id": file_id})
            server_socket.send(packet)

            # Await server response
            response = receive_packet(server_socket)
            handle_boolean_response(response)

        case "replace":
            if len(args) != 3:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._replace}")
            validate_params(file_id=(file_id := args[1]))

            file_path = args[2]
            filename = os.path.basename(file_path)
            new_content = read_file(file_path)

            packet = create_packet(PacketType.REPLACE.value,
                                   {"file_id": file_id})
            server_socket.send(packet)

            # Await server response
            response = receive_packet(server_socket)
            payload  = response.get("payload")
            if response.get("type") == PacketType.ERROR.value:
                print(payload.get("message"))
                return

            user_file_sym_key_bytes = payload.get("key")

            # Decrypt file symmetric key
            file_symmetric_key = RSA.decrypt(user_file_sym_key_bytes, client_private_key)

            # Encrypt new file contents
            enc_content = AES_GCM.encrypt(new_content, file_symmetric_key)
            packet_replace = create_packet(PacketType.REPLACE.value,
                                           {"content": BSON.encode(enc_content),
                                            "size": len(new_content)})
            server_socket.send(packet_replace)

            # Await server response
            response = receive_packet(server_socket)
            handle_boolean_response(response)

        case "details":
            if len(args) != 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._details}")
            validate_params(file_id=(file_id := args[1]))

            packet = create_packet(PacketType.DETAILS.value,
                                   {"file_id": file_id})
            server_socket.send(packet)

            # Await server response
            response = receive_packet(server_socket)
            payload = response.get("payload")
            if response.get("type") == PacketType.ERROR.value:
                print(payload.get("message"))
                return

            for k, v in payload.items():
                if k == "shared_with":
                    if len(v) == 0:
                        print("Shared with no one.")
                    else:
                        print("Shared with:")
                        for share_k, shared_v in v.items():
                            permissions = shared_v.get("permissions")
                            print(f" {share_k} : {permissions}")
                elif k == "group_members":
                    if len(v) == 0:
                        print("No member of a group can see/edit.")
                    else:
                        print("Group members:")
                        for group_id, group_members in v.items():
                            print(f" Group '{group_id}':")
                            for member, info in group_members.items():
                                permissions = info.get("permissions")
                                print(f" |->{member} [{permissions}]")
                else:
                    print(f"{k}: {v}")

        case "revoke":
            if len(args) != 3:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._revoke}")
            validate_params(file_id=(file_id := args[1]),
                            user_id=(user_id := args[2]))

            packet = create_packet(PacketType.REVOKE.value,
                                   {"file_id": file_id, "user_id": user_id})
            server_socket.send(packet)

            # Await server response
            response = receive_packet(server_socket)
            handle_boolean_response(response)

        case "read":
            if len(args) != 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._read}")
            validate_params(file_id=(file_id := args[1]))

            packet = create_packet(PacketType.READ.value,
                                   {"file_id": file_id})
            server_socket.send(packet)

            # Await server response
            response = receive_packet(server_socket)
            payload = response.get("payload")
            if response.get("type") == PacketType.ERROR.value:
                print(payload.get("message"))
                return

            content_enc = BSON.decode(payload.get("content"))
            file_symmetric_key_enc = payload.get("key")

            # Decrypt file symmetric key
            file_symmetric_key = RSA.decrypt(file_symmetric_key_enc, client_private_key)

            # Decrypt file content
            content = AES_GCM.decrypt(content_enc.get("ciphertext"), file_symmetric_key, content_enc.get("iv"), content_enc.get("tag"))

            print(f"File name: {file_id}")
            print(f"Content:\n{content.decode()}")

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

                    # Encrypt master group key with current user public key
                    group_key = RSA.encrypt(group_key, client_public_key)

                    # Send group creation request to server
                    packet = create_packet(PacketType.GROUP_CREATE.value,
                                           {"name": group_id,
                                            "key": group_key})
                    server_socket.send(packet)

                    # Await server boolean response
                    response = receive_packet(server_socket)
                    handle_boolean_response(response)

                case "delete":
                    if len(args) != 3:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_delete}")
                    validate_params(group_id=(group_id := args[2]))

                    # Send group deletion request to server
                    packet = create_packet(PacketType.GROUP_DELETE.value,
                                           {"id": group_id})
                    server_socket.send(packet)

                    # Await server boolean response
                    response = receive_packet(server_socket)
                    handle_boolean_response(response)

                case "add-user":
                    if len(args) != 5:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_add_user}")
                    validate_params(group_id=(group_id := args[2]),
                                    user_id=(user_id := args[3]),
                                    permissions=(permissions := args[4]))

                    # Request master group and user public keys from server (server can deny)
                    packet = create_packet(PacketType.GROUP_ADD_USER_INIT.value,
                                           {"group_id": group_id,
                                            "user_id": user_id})
                    server_socket.send(packet)

                    # Await server response (GROUP_ADD_USER_INIT | ERROR)
                    response = receive_packet(server_socket)
                    payload  = response.get("payload")
                    if response.get("type") == PacketType.ERROR.value:
                        print(payload.get("message"))
                        return

                    # Decrypt the group master key with the current user private key
                    group_key = payload.get("group_key")
                    group_key = RSA.decrypt(group_key, client_private_key)

                    # Encrypt the group master key with the user to add public key
                    public_key = payload.get("public_key")
                    public_key = serialization.load_pem_public_key(public_key)
                    encrypted_group_key = RSA.encrypt(group_key, public_key)

                    # Send the encrypted master group public key to the server
                    packet = create_packet(PacketType.GROUP_ADD_USER.value,
                                           {"group_id": group_id,
                                            "user_id": user_id,
                                            "permissions": permissions,
                                            "group_key": encrypted_group_key})
                    server_socket.send(packet)

                    # Await server response (SUCCESS | ERROR)
                    response = receive_packet(server_socket)
                    handle_boolean_response(response)

                case "delete-user":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_delete_user}")
                    validate_params(group_id=(group_id := args[2]),
                                    user_id=(user_id := args[3]))

                    # Send user group deletion request to server
                    packet = create_packet(PacketType.GROUP_DELETE_USER.value,
                                           {"id": group_id,
                                            "user_id": user_id,
                                            "confirm": False})
                    server_socket.send(packet)

                    # Await server response (NEED_CONFIRMATION | SUCCESS | ERROR)
                    response = receive_packet(server_socket)

                    if response.get("type") == PacketType.NEED_CONFIRMATION.value:
                        print(response.get("payload").get("message"))
                        confirm = input("Do you want to continue? [y/N] ")
                        if confirm.lower() != "y":
                            server_socket.send(create_abort_packet())
                            print("Operation cancelled.")
                            return
                        server_socket.send(create_confirm_packet())

                    handle_boolean_response(response)

                case "list":
                    if len(args) != 2:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_list}")

                    # Send group list request to server
                    packet = create_packet(PacketType.GROUP_LIST.value, {})
                    server_socket.send(packet)

                    # Await server response (GROUP_LIST | ERROR)
                    response = receive_packet(server_socket)
                    payload  = response.get("payload")
                    if response.get("type") == PacketType.ERROR.value:
                        print(payload.get("message"))
                        return

                    # Print the results
                    if len(payload) == 0:
                        print("You have no access to any groups.")
                        return

                    headers = ["Group ID", "Permissions"]
                    print(tabulate(payload.get("groups"), headers=headers, tablefmt="rounded_outline"))

                case "add":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_add}")
                    validate_params(group_id=(group_id := args[2]))

                    file_path = args[3]
                    filename = os.path.basename(file_path)
                    content = read_file(file_path)

                    # Send group master key from current user request to server
                    packet = create_packet(PacketType.GROUP_ADD_INIT.value,
                                           {"group_id": group_id,
                                            "filename": filename,
                                            "size": len(content)})
                    server_socket.send(packet)

                    # Retrieve group master key from server (GROUP_ADD_INIT | ERROR)
                    response = receive_packet(server_socket)
                    payload  = response.get("payload")
                    if response.get("type") == PacketType.ERROR.value:
                        print(payload.get("message"))
                        return

                    group_key = payload.get("group_key")

                    # Decrypt the group master key with the current user private key
                    dec_group_key = RSA.decrypt(group_key, client_private_key)

                    # Encrypt content with group master key
                    enc_content = BSON.encode(AES_GCM.encrypt(content, dec_group_key))

                    # Send add file to group request to server
                    packet = create_packet(PacketType.GROUP_ADD.value,
                                           {"group_id": group_id,
                                            "content": enc_content,
                                            "filename": filename,
                                            "size": len(content),
                                            "group_key": group_key})
                    server_socket.send(packet)

                    # Await server response (SUCCESS | ERROR)
                    response = receive_packet(server_socket)
                    handle_boolean_response(response)

                case "delete-file":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_delete_file}")
                    validate_params(group_id=(group_id := args[2]),
                                    file_id=(file_id := args[3]))

                    # Send group file deletion request to server
                    packet = create_packet(PacketType.GROUP_DELETE_FILE.value,
                                           {"group_id": group_id,
                                            "file_id": file_id})
                    server_socket.send(packet)

                    # Await server response
                    response = receive_packet(server_socket)
                    handle_boolean_response(response)

                case "change-permissions":
                    if len(args) != 5:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_change_permissions}")
                    validate_params(group_id=(group_id := args[2]),
                                    user_id=(user_id := args[3]),
                                    permissions=(permissions := args[4]))

                    # Send group file deletion request to server
                    packet = create_packet(PacketType.GROUP_CHANGE_PERMISSIONS.value,
                                           {"group_id": group_id,
                                            "user_id": user_id,
                                            "permissions": permissions})
                    server_socket.send(packet)

                    # Await server response
                    response = receive_packet(server_socket)
                    handle_boolean_response(response)

                case "add-moderator":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_add_moderator}")
                    validate_params(group_id=(group_id := args[2]),
                                    user_id=(user_id := args[3]))

                    # Send user id to be promoted to the server
                    packet = create_packet(PacketType.GROUP_ADD_MODERATOR.value,
                                           {"group_id": group_id,
                                            "user_id": user_id})
                    server_socket.send(packet)

                    # Await server response (GROUP_ADD_MODERATOR | ERROR)
                    response = receive_packet(server_socket)
                    payload = response.get("payload")
                    if response.get("type") == PacketType.ERROR.value:
                        print(payload.get("message"))
                        return

                    group_key_enc = payload.get("group_key")
                    user_pub_key_bytes = payload.get("public_key")
                    user_pub_key = serialization.load_pem_public_key(user_pub_key_bytes)

                    # Decrypt the group master key with the current user private key
                    group_key_dec = RSA.decrypt(group_key_enc, client_private_key)

                    # Encrypt the group master key with the moderator public key
                    group_key_enc = RSA.encrypt(group_key_dec, user_pub_key)

                    packet_add_moderator = create_packet(PacketType.GROUP_ADD_MODERATOR.value,
                                                         {"key": group_key_enc})
                    server_socket.send(packet_add_moderator)

                    # Await server response (SUCCESS | ERROR)
                    response = receive_packet(server_socket)
                    handle_boolean_response(response)

                case "remove-moderator":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_remove_moderator}")
                    validate_params(group_id=(group_id := args[2]),
                                    user_id=(user_id := args[3]))

                    # Send user id to be promoted to server
                    packet = create_packet(PacketType.GROUP_REMOVE_MODERATOR.value,
                                           {"group_id": group_id,
                                            "moderator_id": user_id})
                    server_socket.send(packet)

                    # Await server response
                    response = receive_packet(server_socket)
                    handle_boolean_response(response)
                case _:
                    raise ValueError(f"Invalid command: group '{group_command}'\n"
                                     f"{usage._group}")
        case "logs":
            if len(args) < 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._logs}")

            logs_command = args[1]
            match logs_command:
                case "global":
                    if len(args) == 2:
                        # Send user id to the server
                        packet = create_packet(PacketType.LOGS_GLOBAL.value)
                        server_socket.send(packet)

                        # Await server response (LOGS_GLOBAL | ERROR)
                        response = receive_packet(server_socket)
                        payload  = response.get("payload")
                        if response.get("type") == PacketType.ERROR.value:
                            print(payload.get("message"))
                            return

                        print_logs(payload.get("logs"))

                    elif len(args) == 4:
                        if args[2] != "-g":
                            raise ValueError(f"Invalid arguments.\nUsage: {usage._logs_user_global}")
                        validate_params(group_id=(group_id := args[3]))

                        # Send group id to the server
                        packet = create_packet(PacketType.LOGS_GROUP_OWNER.value,
                                               {"group_id": group_id})
                        server_socket.send(packet)

                        # Await server response (LOGS_GROUP_OWNER | ERROR)
                        response = receive_packet(server_socket)
                        payload  = response.get("payload")
                        if response.get("type") == PacketType.ERROR.value:
                            print(payload.get("message"))
                            return

                        print_logs(payload.get("logs"))

                    else:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._logs_user_global}")

                case "file":
                    if len(args) != 3:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._logs_user_file}")
                    validate_params(file_id=(file_id := args[2]))

                    # Send file id to the server
                    packet = create_packet(PacketType.LOGS_FILE.value,
                                           {"file_id": file_id})
                    server_socket.send(packet)

                    # Await server response (LOGS_FILE | ERROR)
                    response = receive_packet(server_socket)
                    payload  = response.get("payload")
                    if response.get("type") == PacketType.ERROR.value:
                        print(payload.get("message"))
                        return

                    print_logs(payload.get("logs"))

                case "group":
                    if len(args) != 3:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._logs}")

                    validate_params(group_id=(group_id := args[2]))

                    # Send group id to the server
                    packet = create_packet(PacketType.LOGS_GROUP.value,
                                           {"group_id": group_id})
                    server_socket.send(packet)

                    # Await server response (LOGS_GROUP | ERROR)
                    response = receive_packet(server_socket)
                    payload  = response.get("payload")
                    if response.get("type") == PacketType.ERROR.value:
                        print(payload.get("message"))
                        return

                    print_logs(payload.get("logs"))

                case _:
                    raise ValueError(f"Invalid arguments.\nUsage: {usage._logs}")
        case _:
            raise ValueError(f"Invalid command: '{command}'\n{usage._full}")
