import ssl
import json
import base64
from server.operations import Operations
from common.exceptions import NeedConfirmation
from common.packet import (
    CommandType,
    create_packet,
    create_success_packet,
    create_error_packet,
    create_need_confirmation_packet,
    decode_packet,
    receive_packet
)


def process_request(operations: Operations, current_user_id: str, conn: ssl.SSLSocket, packet_data: bytes):
    try:
        packet = decode_packet(packet_data)  # TODO decode_packet before calling process_request
        payload = packet.get("payload")
        match packet.get("type"):
            case CommandType.ADD_REQUEST.value:
                content  = payload.get("content")
                file_key = payload.get("key")
                size     = payload.get("size")
                filename = payload.get("filename")
                file_id = f"{current_user_id}:{filename}"
                try:
                    file_key = base64.b64encode(file_key).decode("utf-8")
                    operations.add_file_to_user(current_user_id, filename, content, file_key, size)
                    conn.send(create_success_packet(f"File ID: {current_user_id}:{filename}"))
                    operations.logs.add_user_entry(current_user_id, filename, True,  file_id=file_id)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, filename, False, file_id=file_id)

            case CommandType.LIST_REQUEST.value:
                try:
                    if user_id := payload.get("user_id"):
                        command = f"list -u {user_id}"
                        payload = operations.list_user_shared_files(current_user_id, user_id)
                    elif group_id := payload.get("group_id"):
                        command = f"list -g {group_id}"
                        payload = operations.list_user_group_files(current_user_id, group_id)
                    elif not payload:
                        command = "list"
                        payload = operations.list_user_personal_files(current_user_id)

                    conn.send(create_packet(CommandType.LIST_RESPONSE.value, payload))
                    operations.logs.add_user_entry(current_user_id, command, True)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, command, False)

            case CommandType.SHARE_REQUEST_VALIDATION.value:  # TODO name the type as SHARE_REQUEST
                file_id     = payload.get("file_id")
                user_id     = payload.get("user_id")
                permissions = payload.get("permissions")
                try:
                    public_key, file_key = operations.init_share_user_file(current_user_id, file_id, user_id, permissions)
                    intermediate_packet = create_packet(CommandType.SHARE_RESPONSE_VALIDATION.value,  # TODO name the type as SHARE_RESPONSE
                                                        {"public_key": base64.b64decode(public_key),
                                                         "file_symmetric_key": base64.b64decode(file_key)})
                    conn.send(intermediate_packet)

                    # Await client response with encrypted file key
                    client_response_packet = receive_packet(conn)

                    file_key = client_response_packet.get("payload").get("key")
                    file_key = base64.b64encode(file_key).decode("utf-8")
                    operations.share_user_file(current_user_id, file_id, user_id, permissions, file_key)

                    conn.send(create_success_packet(f"Successfully shared file '{file_id}' with user '{user_id}'."))
                    operations.logs.add_user_entry(current_user_id, f"share {file_id} {user_id} {permissions}", True,
                                                   file_id=file_id)
                    operations.logs.add_user_entry(user_id, f"share {file_id} {user_id} {permissions}", True,
                                                   file_id=file_id, executor_id=current_user_id)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"share {file_id} {user_id} {permissions}", False,
                                                   file_id=file_id)

            case CommandType.DELETE_REQUEST.value:  # TODO users that had access via share or group don't have the log entry
                file_id = payload.get("file_id")
                try:
                    operations.delete_file(current_user_id, file_id)
                    conn.send(create_success_packet(f"Successfully deleted file '{file_id}'."))
                    operations.logs.add_user_entry(current_user_id, f"delete {file_id}", True, file_id=file_id)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"delete {file_id}", False, file_id=file_id)

            # TODO users that have access via share or group don't have the log entry
            case CommandType.REPLACE_REQUEST_VALIDATION.value:  # TODO name the type as REPLACE_REQUEST
                file_id = payload.get("file_id")
                try:
                    file_key = operations.init_replace_file(current_user_id, file_id)
                    intermediate_packet = create_packet(CommandType.REPLACE_RESPONSE_VALIDATION.value,  # TODO name the type as REPLACE_RESPONSE
                                                        {"key": base64.b64decode(file_key)})
                    conn.send(intermediate_packet)

                    # Await client response with encrypted new file content
                    client_response_packet = receive_packet(conn)

                    new_content = client_response_packet.get("payload").get("content")
                    new_size = client_response_packet.get("payload").get("size")
                    operations.replace_file(current_user_id, file_id, new_content, new_size)
                    conn.send(create_success_packet(f"File '{file_id}' replaced with new content."))
                    operations.logs.add_user_entry(current_user_id, f"replace {file_id}", True, file_id=file_id)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"replace {file_id}", False, file_id=file_id)

            case CommandType.DETAILS_REQUEST.value:
                file_id = payload.get("file_id")
                try:
                    details = operations.file_details(current_user_id, file_id)
                    conn.send(create_packet(CommandType.DETAILS_RESPONSE.value, details))
                    operations.logs.add_user_entry(current_user_id, f"details {file_id}", True, file_id=file_id)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"details {file_id}", False, file_id=file_id)

            case CommandType.REVOKE_REQUEST.value:
                file_id = payload.get("file_id")
                user_id = payload.get("user_id")
                try:
                    operations.revoke_user_file_permissions(current_user_id, file_id, user_id)
                    conn.send(create_success_packet(f"Successfully revoked permissions of user "
                                                    f"'{user_id} on file {file_id}'."))
                    operations.logs.add_user_entry(current_user_id, f"revoke {file_id} {user_id}", True,
                                                   file_id=file_id)
                    operations.logs.add_user_entry(user_id, f"revoke {file_id} {user_id}", True,
                                                   file_id=file_id, executor_id=current_user_id)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"revoke {file_id} {user_id}", False,
                                                   file_id=file_id)

            case CommandType.READ_REQUEST.value:
                try:
                    file_id = payload.get("file_id")
                    file = operations.read_file(current_user_id, file_id)

                    file_content = file.get("file_contents")
                    file_key = base64.b64decode(file.get("key"))

                    conn.send(create_packet(CommandType.READ_RESPONSE.value,
                                            {"content": file_content,
                                             "key": file_key}))
                    operations.logs.add_user_entry(current_user_id, f"read {file_id}", True, file_id=file_id)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"read {file_id}", False, file_id=file_id)

            case CommandType.GROUP_CREATE_REQUEST.value:
                group_name = payload.get("name")
                group_key  = payload.get("key")
                try:
                    group_key = base64.b64encode(group_key).decode("utf-8")
                    group_id = operations.create_group(current_user_id, group_name, group_key)
                    conn.send(create_success_packet(message=f"Group ID: {group_id}"))
                    operations.logs.add_user_entry(current_user_id, f"group create {group_name}", True, group_id=group_name)
                    operations.logs.add_group_entry(current_user_id, group_name, f"group create {group_name}", True)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"group create {group_name}", False, group_id=group_name)

            case CommandType.GROUP_DELETE_REQUEST.value:
                group_id = payload.get("id")
                try:
                    operations.delete_group(current_user_id, group_id)
                    conn.send(create_success_packet())
                    operations.logs.add_user_entry(current_user_id, f"group delete {group_id}", True, group_id=group_id)
                    operations.logs.add_group_entry(current_user_id, group_id, f"group delete {group_id}", True)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"group delete {group_id}", False, group_id=group_id)

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
                    operations.logs.add_user_entry(current_user_id, f"group add-user {group_id} {user_id} {permissions}", True,
                                                   group_id=group_id)
                    operations.logs.add_group_entry(current_user_id, group_id, f"group add-user {group_id} {user_id} {permissions}", True)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"group add-user {group_id} {user_id} {permissions}", False,
                                                   group_id=group_id)

            case CommandType.GROUP_DELETE_USER_REQUEST.value:
                group_id = payload.get("id")
                user_id  = payload.get("user_id")
                confirm  = payload.get("confirm", False)
                try:
                    # TODO include files in NeedConfirmation exception message
                    operations.remove_user_from_group(current_user_id, group_id, user_id, confirm)
                    conn.send(create_success_packet())
                except NeedConfirmation as e:
                    conn.send(create_need_confirmation_packet(str(e)))

                    client_response = receive_packet(conn)
                    if client_response.get("type") == CommandType.CONFIRM.value:
                        try:
                            operations.remove_user_from_group(current_user_id, group_id, user_id, True)
                            conn.send(create_success_packet())
                            operations.logs.add_user_entry(current_user_id, f"group delete-user {group_id} {user_id}", True,
                                                           group_id=group_id)
                            operations.logs.add_group_entry(current_user_id, group_id, f"group delete-user {group_id} {user_id}", True)
                        except Exception as e:
                            conn.send(create_error_packet(str(e)))
                            operations.logs.add_user_entry(current_user_id, f"group delete-user {group_id} {user_id}", False,
                                                           group_id=group_id)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"group delete-user {group_id} {user_id}", False,
                                                   group_id=group_id)

            case CommandType.GROUP_LIST_REQUEST.value:
                try:
                    group_info = operations.list_user_groups(current_user_id)
                    group_info = json.dumps(group_info, indent=2)
                    conn.send(create_success_packet(message=group_info))
                    operations.logs.add_user_entry(current_user_id, "group list", True)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, "group list", False)

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
                    operations.logs.add_user_entry(current_user_id, f"group add {group_id} {filename}", True,
                                                   group_id=group_id)
                    operations.logs.add_group_entry(current_user_id, group_id, f"group add {group_id} {filename}", True)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"group add {group_id} {filename}", False,
                                                   group_id=group_id)

            case CommandType.GROUP_DELETE_FILE_REQUEST.value:
                group_id = payload.get("group_id")
                file_id  = payload.get("file_id")
                try:
                    operations.delete_file_from_group(current_user_id, group_id, file_id)
                    conn.send(create_success_packet())
                    operations.logs.add_user_entry(current_user_id, f"group delete-file {group_id} {file_id}", True,
                                                   group_id=group_id)
                    operations.logs.add_group_entry(current_user_id, group_id, f"group delete-file {group_id} {file_id}", True)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"group delete-file {group_id} {file_id}", False,
                                                   group_id=group_id)

            case CommandType.GROUP_CHANGE_PERMISSIONS_REQUEST.value:
                group_id    = payload.get("group_id")
                user_id     = payload.get("user_id")
                permissions = payload.get("permissions")
                try:
                    operations.change_user_group_permissions(current_user_id, group_id, user_id, permissions)
                    conn.send(create_success_packet())
                    operations.logs.add_user_entry(current_user_id, f"group change-permissions {group_id} {user_id} {permissions}", True,
                                                   group_id=group_id)
                    operations.logs.add_group_entry(current_user_id, group_id, f"group change-permissions {group_id} {user_id} {permissions}", True)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"group change-permissions {group_id} {user_id} {permissions}", False,
                                                   group_id=group_id)

            case CommandType.GROUP_ADD_MODERATOR_REQUEST.value:
                user_id = payload.get("user_id")
                group_id = payload.get("group_id")
                try:
                    user_group_key, user_pub_key = operations.init_add_moderator_to_group(current_user_id, group_id, user_id)
                    user_group_key = base64.b64decode(user_group_key)
                    user_pub_key   = base64.b64decode(user_pub_key)

                    intermediate_packet = create_packet(CommandType.GROUP_ADD_MODERATOR_RESPONSE_WITH_KEYS.value,
                                                        {"group_key": user_group_key,
                                                         "public_key": user_pub_key})
                    conn.send(intermediate_packet)

                    # Await client response with group key encrypted with user public key
                    client_response_packet = receive_packet(conn)

                    group_key = base64.b64encode(client_response_packet.get("payload").get("key")).decode("utf-8")
                    operations.add_moderator_to_group(current_user_id, group_id, user_id, group_key)
                    conn.send(create_success_packet(f"Successfully added user '{user_id}' as a moderator on group '{group_id}'."))
                    operations.logs.add_user_entry(current_user_id, f"group add-moderator {group_id} {user_id}", True,
                                                   group_id=group_id)
                    operations.logs.add_group_entry(current_user_id, group_id, f"group add-moderator {group_id} {user_id}", True)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"group add-moderator {group_id} {user_id}", False,
                                                   group_id=group_id)

            case CommandType.GROUP_REMOVE_MODERATOR_REQUEST.value:
                group_id = payload.get("group_id")
                moderator_id = payload.get("moderator_id")
                try:
                    operations.remove_moderator_from_group(current_user_id, group_id, moderator_id)
                    conn.send(create_success_packet(f"Successfully demoted moderator '{moderator_id}' from group '{group_id}'."))
                    operations.logs.add_user_entry(current_user_id, f"group remove-moderator {group_id} {moderator_id}", True,
                                                   group_id=group_id)
                    operations.logs.add_group_entry(current_user_id, group_id, f"group remove-moderator {group_id} {moderator_id}", True)
                except Exception as e:
                    conn.send(create_error_packet(str(e)))
                    operations.logs.add_user_entry(current_user_id, f"group remove-moderator {group_id} {moderator_id}", False,
                                                   group_id=group_id)

            case CommandType.LOGS_GLOBAL_REQUEST.value:
                try:
                    logs = operations.list_user_logs(current_user_id)
                    response = create_packet(CommandType.LOGS_GLOBAL_RESPONSE.value,
                                             {"logs": logs})
                except Exception as e:
                    response = create_error_packet(str(e))
                finally:
                    conn.send(response)

            case CommandType.LOGS_FILE_REQUEST.value:
                try:
                    file_id = payload.get("file_id")
                    logs = operations.list_user_file_logs(current_user_id, file_id)
                    response = create_packet(CommandType.LOGS_FILE_RESPONSE.value,
                                             {"logs": logs})
                except Exception as e:
                    response = create_error_packet(str(e))
                finally:
                    conn.send(response)

            case CommandType.LOGS_GROUP_REQUEST.value:
                try:
                    group_id = payload.get("group_id")
                    logs = operations.list_user_group_logs(current_user_id, group_id)
                    response = create_packet(CommandType.LOGS_GROUP_RESPONSE.value,
                                             {"logs": logs})
                except Exception as e:
                    response = create_error_packet(str(e))
                finally:
                    conn.send(response)

            case CommandType.LOGS_GROUP_OWNER_REQUEST.value:
                try:
                    group_id = payload.get("group_id")
                    logs = operations.list_group_logs(current_user_id, group_id)
                    response = create_packet(CommandType.LOGS_GROUP_OWNER_RESPONSE.value,
                                             {"logs": logs})
                except Exception as e:
                    response = create_error_packet(str(e))
                finally:
                    conn.send(response)

    except Exception as e:
        print(e)
