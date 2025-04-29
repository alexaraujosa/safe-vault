import ssl
import json
import base64
from bson import BSON
from server.operations import Operations
from common.exceptions import NeedConfirmation
from common.packet import (
    CommandType,
    create_packet,
    create_success_packet,
    create_error_packet,
    create_need_confirmation_packet,
    decode_packet
)


def process_request(operations: Operations, current_user_id: str, conn: ssl.SSLSocket, packet_data: bytes):
    try:
        packet = decode_packet(packet_data)
        payload = packet.get("payload")
        match packet.get("type"):
            case CommandType.ADD_REQUEST.value:
                content  = payload.get("content")
                file_key = payload.get("key")
                size     = payload.get("size")
                filename = payload.get("filename")
                try:
                    file_key = base64.b64encode(file_key).decode("utf-8")
                    operations.add_file_to_user(current_user_id, filename, content, file_key, size)
                    conn.send(create_success_packet(f"File '{filename}' added successfully to the vault."))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.LIST_REQUEST.value:
                try:
                    if user_id := payload.get("user_id"):  # list -u <user_id>
                        payload = operations.list_user_shared_files(current_user_id, user_id)
                    elif group_id := payload.get("group_id"):  # list -g <group_id>
                        payload = operations.list_user_group_files(current_user_id, group_id)
                    elif not payload:
                        payload = operations.list_user_personal_files(current_user_id)

                    conn.send(create_packet(CommandType.LIST_RESPONSE.value, payload))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.SHARE_REQUEST_VALIDATION.value:
                file_id     = payload.get("file_id")
                user_id     = payload.get("user_id")
                permissions = payload.get("permissions")
                try:
                    public_key, file_key = operations.validate_share_user_file(current_user_id, file_id, user_id, permissions)

                    intermediate_packet = create_packet(CommandType.SHARE_RESPONSE_VALIDATION.value,
                                                        {"public_key": base64.b64decode(public_key),
                                                         "file_symmetric_key": base64.b64decode(file_key)})
                    conn.send(intermediate_packet)

                    # Await client response with encrypted file key
                    client_response_packet = decode_packet(conn.recv())

                    file_key = client_response_packet.get("payload").get("key")
                    file_key = base64.b64encode(file_key).decode("utf-8")
                    operations.share_user_file(current_user_id, file_id, user_id, permissions, file_key)

                    conn.send(create_success_packet(f"Successfully shared file '{file_id}' with user '{user_id}'."))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.DELETE_REQUEST.value:
                file_id = payload.get("file_id")
                try:
                    operations.delete_file(current_user_id, file_id)
                    conn.send(create_success_packet(f"Successfully deleted file '{file_id}'."))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.REPLACE_REQUEST_VALIDATION.value:
                file_id = payload.get("file_id")
                try:
                    file_key = operations.validate_replace_file(current_user_id, file_id)
                    intermediate_packet = create_packet(CommandType.REPLACE_RESPONSE_VALIDATION.value,
                                                        {"key": base64.b64decode(file_key)})
                    conn.send(intermediate_packet)

                    # Await client response with encrypted new file content
                    client_response_packet = decode_packet(conn.recv())

                    new_content = client_response_packet.get("payload").get("content")
                    new_size = client_response_packet.get("payload").get("size")
                    operations.replace_file(current_user_id, file_id, new_content, new_size)

                    conn.send(create_success_packet(f"File '{file_id}' replaced with new content."))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.DETAILS_REQUEST.value:
                file_id = payload.get("file_id")
                try:
                    details = operations.file_details(current_user_id, file_id)
                    conn.send(create_packet(CommandType.DETAILS_RESPONSE.value, details))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.REVOKE_REQUEST.value:
                file_id = payload.get("file_id")
                user_id = payload.get("user_id")
                try:
                    operations.revoke_user_file_permissions(current_user_id, file_id, user_id)
                    conn.send(create_success_packet(f"Successfully revoked permissions of user "
                                                    f"'{user_id} on file {file_id}'."))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.READ_REQUEST.value:
                try:
                    file_id = payload.get("file_id")
                    file = operations.read_file(current_user_id, file_id)

                    file_content = file.get("file_contents")
                    file_key = base64.b64decode(file.get("key"))

                    response = create_packet(CommandType.READ_RESPONSE.value,
                                             {"content": file_content,
                                              "key": file_key})
                except Exception as e:
                    response = create_error_packet(str(e))
                finally:
                    conn.send(response)

            case CommandType.GROUP_CREATE_REQUEST.value:
                group_name = payload.get("name")
                group_key  = payload.get("key")
                try:
                    group_key = base64.b64encode(group_key).decode("utf-8")
                    group_id = operations.create_group(current_user_id, group_name, group_key)
                    conn.send(create_success_packet(message=f"Group ID: {group_id}"))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.GROUP_DELETE_REQUEST.value:
                group_id = payload.get("id")
                try:
                    operations.delete_group(current_user_id, group_id)
                    conn.send(create_success_packet())
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.INIT_GROUP_ADD_USER_REQUEST.value:
                group_id = payload.get("group_id")
                user_id  = payload.get("user_id")
                try:
                    group_key, user_public_key = operations.init_add_user_to_group(current_user_id, group_id, user_id)
                    server_response = create_packet(CommandType.INIT_GROUP_ADD_USER_RESPONSE.value,
                                                    {"group_key": base64.b64decode(group_key),
                                                     "public_key": base64.b64decode(user_public_key)})
                    conn.send(server_response)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.GROUP_ADD_USER_REQUEST.value:
                group_id    = payload.get("group_id")
                user_id     = payload.get("user_id")
                permissions = payload.get("permissions")
                group_key   = payload.get("group_key")
                try:
                    group_key = base64.b64encode(group_key).decode("utf-8")
                    message = operations.add_user_to_group(current_user_id, group_id, user_id, permissions, group_key)
                    conn.send(create_success_packet(message=message))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.GROUP_DELETE_USER_REQUEST.value:
                group_id = payload.get("id")
                user_id  = payload.get("user_id")
                confirm  = payload.get("confirm", False)
                try:
                    operations.remove_user_from_group(current_user_id, group_id, user_id, confirm)
                    conn.send(create_success_packet())
                except NeedConfirmation as e:
                    conn.send(create_need_confirmation_packet(str(e)))

                    client_response = decode_packet(conn.recv())
                    if client_response.get("type") == CommandType.CONFIRM.value:
                        try:
                            operations.remove_user_from_group(current_user_id, group_id, user_id, True)
                            conn.send(create_success_packet())
                        except Exception as e:
                            conn.send(create_error_packet(str(e)))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.GROUP_LIST_REQUEST.value:
                try:
                    group_info = operations.list_user_groups(current_user_id)
                    group_info = json.dumps(group_info, indent=2)
                    conn.send(create_success_packet(message=group_info))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.INIT_GROUP_ADD_REQUEST.value:
                group_id = payload.get("group_id")
                filename = payload.get("filename")
                size     = payload.get("size")
                try:
                    group_key = operations.init_add_file_to_group(current_user_id, group_id, filename, size)
                    server_response = create_packet(CommandType.INIT_GROUP_ADD_RESPONSE.value,
                                                    {"group_key": base64.b64decode(group_key)})
                    conn.send(server_response)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.GROUP_ADD_REQUEST.value:
                group_id  = payload.get("group_id")
                content   = payload.get("content")
                filename  = payload.get("filename")
                size      = payload.get("size")
                group_key = payload.get("group_key")
                try:
                    group_key = base64.b64encode(group_key).decode("utf-8")
                    file_id = operations.add_file_to_group(current_user_id, group_id, filename, content, size, group_key)
                    conn.send(create_success_packet(f"File ID: {file_id}"))
                except Exception as e:
                    conn.send(create_error_packet(str(e)))

            case CommandType.GROUP_DELETE_FILE_REQUEST.value:
                # TODO group delete-file
                pass

    except Exception as e:
        print(e)
