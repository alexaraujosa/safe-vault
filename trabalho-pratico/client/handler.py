import os
from bson import BSON
from cryptography.hazmat.primitives import serialization
import client.usage as usage
from client.encryption import RSA, AES_GCM
from common.validation import validate_params
from common.packet import (
    CommandType,
    create_packet,
    # create_success_packet,
    # create_error_packet,
    create_confirm_packet,
    create_abort_packet,
    decode_packet
)


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

            filename = os.path.basename(file_path)
            content = read_file(file_path)

            # Create file master key with AES
            file_key = AES_GCM.generate_key()

            # Encrypt content with symmetric key
            enc_content = BSON.encode(AES_GCM.encrypt(content, file_key))

            # Encrypt file master key with client public key
            enc_file_key = RSA.encrypt(file_key, client_public_key)

            packet = create_packet(CommandType.ADD_REQUEST.value,
                                   {"content": enc_content,
                                    "key": enc_file_key,
                                    "size": len(content),
                                    "filename": filename})
            server_socket.send(packet)

            # Await server response
            response = decode_packet(server_socket.recv())
            handle_boolean_response(response)

        case "list":
            rest = args[1:]
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

            server_socket.send(packet)

            # Await server response and print the list results
            response = decode_packet(server_socket.recv())
            payload = response.get("payload")
            if response.get("type") == CommandType.ERROR.value:
                print(payload.get("message"))
            elif CommandType.LIST_RESPONSE.value:
                if len(payload) == 0:
                    print("No files found on own vault.")

                for entry in payload:
                    print(entry)

        case "share":
            if len(args) != 4:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._share}")
            validate_params(file_id=(file_id := args[1]),
                            user_id=(user_id := args[2]),
                            permissions=(permissions := args[3]))

            packet = create_packet(CommandType.SHARE_REQUEST_VALIDATION.value,
                                   {"file_id": file_id,
                                    "user_id": user_id,
                                    "permissions": permissions})
            server_socket.send(packet)

            # Await server response
            response_validation = decode_packet(server_socket.recv())

            if response_validation.get("type") == CommandType.SHARE_RESPONSE_VALIDATION.value:
                user_pub_key_bytes = response_validation.get("payload").get("public_key")
                user_pub_key = serialization.load_pem_public_key(user_pub_key_bytes)
                file_symmetric_key_enc = response_validation.get("payload").get("file_symmetric_key")

                # Decrypt file symmetric key
                file_symmetric_key = RSA.decrypt(file_symmetric_key_enc, client_private_key)

                # Encrypt file symmetric key with share user public key
                share_user_file_symmetric_key_enc = RSA.encrypt(file_symmetric_key, user_pub_key)

                # Send share user file symmetric key to server
                packet_share = create_packet(CommandType.SHARE_REQUEST_WITH_KEY.value,
                                             {"key": share_user_file_symmetric_key_enc})
                server_socket.send(packet_share)

                # Await server response
                response_share = decode_packet(server_socket.recv())

                handle_boolean_response(response_share)
            else:
                handle_boolean_response(response_validation)

        case "delete":
            if len(args) != 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._delete}")
            validate_params(file_id=(file_id := args[1]))

            packet = create_packet(CommandType.DELETE_REQUEST.value,
                                   {"file_id": file_id})
            server_socket.send(packet)

            # Await server response
            response = decode_packet(server_socket.recv())
            handle_boolean_response(response)

        case "replace":
            if len(args) != 3:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._replace}")
            validate_params(file_id=(file_id := args[1]),
                            file_path=(file_path := args[2]))

            filename = os.path.basename(file_path)
            try:
                with open(file_path, "rb") as file:
                    new_content = file.read()

                packet = create_packet(CommandType.REPLACE_REQUEST_VALIDATION.value,
                                       {"file_id": file_id})
                server_socket.send(packet)

                # Await server response
                response_validation = decode_packet(server_socket.recv())

                if response_validation.get("type") == CommandType.REPLACE_RESPONSE_VALIDATION.value:
                    user_file_sym_key_bytes = response_validation.get("payload").get("key")
                    
                    # Decrypt file symmetric key
                    file_symmetric_key = RSA.decrypt(user_file_sym_key_bytes, client_private_key)

                    # Encrypt new file contents
                    content_enc = AES_GCM.encrypt(new_content, file_symmetric_key)
                    packet_replace = create_packet(CommandType.REPLACE_REQUEST_WITH_CONTENT.value,
                                                   {"content": BSON.encode(content_enc),
                                                    "size": len(new_content)})
                    
                    server_socket.send(packet_replace)

                    # Await server response
                    response = decode_packet(server_socket.recv())
                    handle_boolean_response(response)
                else:
                    handle_boolean_response(response_validation)
                    
            except Exception as e:
                print(e)

            new_content = read_file(file_path)
            print(new_content)
            # TODO Encrypt new content

        case "details":
            if len(args) != 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._details}")
            validate_params(file_id=(file_id := args[1]))

            packet = create_packet(CommandType.DETAILS_REQUEST.value,
                                   {"file_id": file_id})
            server_socket.send(packet)

            # Await server response
            response = decode_packet(server_socket.recv())
            if response.get("type") == CommandType.DETAILS_RESPONSE.value:
                for k, v in response.get("payload").items():
                    print(f"{k}: {v}")
            else:
                handle_boolean_response(response)

        case "revoke":
            if len(args) != 3:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._revoke}")
            validate_params(file_id=(file_id := args[1]),
                            user_id=(user_id := args[2]))

            packet = create_packet(CommandType.REVOKE_REQUEST.value,
                                   {"file_id": file_id, "user_id": user_id})
            server_socket.send(packet)

            # Await server response
            response = decode_packet(server_socket.recv())
            handle_boolean_response(response)

        case "read":
            if len(args) != 2:
                raise ValueError(f"Invalid arguments.\nUsage: {usage._read}")
            validate_params(file_id=(file_id := args[1]))

            packet = create_packet(CommandType.READ_REQUEST.value,
                                   {"file_id": file_id})
            
            server_socket.send(packet)

            # Await server response
            response = decode_packet(server_socket.recv())
            if response.get("type") == CommandType.READ_RESPONSE.value:
                content_enc = BSON.decode(response.get("payload").get("content"))
                file_symmetric_key_enc = response.get("payload").get("key")

                # Decrypt file symmetric key
                file_symmetric_key = RSA.decrypt(file_symmetric_key_enc, client_private_key)

                # Decrypt file content
                content = AES_GCM.decrypt(content_enc.get("ciphertext"), file_symmetric_key, content_enc.get("iv"), content_enc.get("tag"))

                print(f"file name: {file_id}")
                print(f"content:\n{content.decode()}")
            else:
                handle_boolean_response(response)
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
                    packet = create_packet(CommandType.GROUP_CREATE_REQUEST.value,
                                           {"name": group_id,
                                            "key": group_key})
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
                                           {"id": group_id})
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

                    # Request master group and user public keys from server (server can deny)
                    packet = create_packet(CommandType.INIT_GROUP_ADD_USER_REQUEST.value,
                                           {"group_id": group_id,
                                            "user_id": user_id})
                    server_socket.send(packet)

                    # Await server response (INIT_GROUP_ADD_USER_RESPONSE | ERROR)
                    response = decode_packet(server_socket.recv())
                    if response.get("type") == CommandType.ERROR.value:
                        print(response.get("payload").get("message"))
                        return

                    # Decrypt the group master key with the current user private key
                    group_key = response.get("payload").get("group_key")
                    group_key = RSA.decrypt(group_key, client_private_key)

                    # Encrypt the group master key with the user to add public key
                    public_key = response.get("payload").get("public_key")
                    public_key = serialization.load_pem_public_key(public_key)
                    encrypted_group_key = RSA.encrypt(group_key, public_key)

                    # Send the encrypted master group public key to the server
                    packet = create_packet(CommandType.GROUP_ADD_USER_REQUEST.value,
                                           {"group_id": group_id,
                                            "user_id": user_id,
                                            "permissions": permissions,
                                            "group_key": encrypted_group_key})
                    server_socket.send(packet)

                    # Await server response (SUCCESS | ERROR)
                    response = decode_packet(server_socket.recv())
                    handle_boolean_response(response)

                case "delete-user":  # TODO test this
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_delete_user}")
                    validate_params(group_id=(group_id := args[2]),
                                    user_id=(user_id := args[3]))

                    # Send user group deletion request to server
                    packet = create_packet(CommandType.GROUP_DELETE_USER_REQUEST.value,
                                           {"id": group_id,
                                            "user_id": user_id,
                                            "confirm": False})
                    server_socket.send(packet)

                    # Await server response (NEED_CONFIRMATION | SUCCESS | ERROR)
                    response = decode_packet(server_socket.recv())

                    if response.get("type") == CommandType.NEED_CONFIRMATION.value:
                        print(response.get("payload").get("message"))
                        confirm = input("Do you want to continue? [y/N] ")
                        if confirm.lower() == "y":
                            server_socket.send(create_confirm_packet())
                        else:
                            server_socket.send(create_abort_packet())
                            print("Operation cancelled.")
                            return

                    handle_boolean_response(response)

                case "list":
                    if len(args) != 2:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_list}")

                    # Send group list request to server
                    packet = create_packet(CommandType.GROUP_LIST_REQUEST.value, {})
                    server_socket.send(packet)

                    # Await server response (SUCCESS | ERROR)
                    response = decode_packet(server_socket.recv())
                    print(response.get("payload").get("message"))

                case "add":
                    if len(args) != 4:
                        raise ValueError(f"Invalid arguments.\nUsage: {usage._group_add}")
                    validate_params(group_id=(group_id := args[2]),
                                    file_path=(file_path := args[3]))

                    content = read_file(file_path)

                    # TODO Retrieve file_:name from the file_path (use basename)
                    # TODO Ask server for group public key (server can deny, e.g. permissions, group not found)
                    # TODO Encrypt content with group public key
                    # TODO Send add file to group request to server (check for server response)
                case _:
                    raise ValueError(f"Invalid command: group '{group_command}'\n"
                                     f"{usage._group}")

                # TODO change user permissions
                # TODO delete-file
                # TODO add-moderator
                # TODO delete-moderator
        case _:
            raise ValueError(f"Invalid command: '{command}'\n{usage._full}")
