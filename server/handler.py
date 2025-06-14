import ssl
import base64
from server.operations import Operations
from common.exceptions import NeedConfirmation
from common.packet import (
    PacketType,
    create_packet,
    create_success_packet,
    create_error_packet,
    create_need_confirmation_packet,
    receive_packet
)


def process_request(operations: Operations, current_user_id: str, conn: ssl.SSLSocket, packet: dict):
    payload = packet.get("payload")
    match packet.get("type"):
        case PacketType.ADD.value:
            content  = payload.get("content")
            file_key = payload.get("key")
            size     = payload.get("size")
            filename = payload.get("filename")
            file_id = f"{current_user_id}:{filename}"
            try:
                file_key = base64.b64encode(file_key).decode("utf-8")
                operations.add_file_to_user(current_user_id, filename, content, file_key, size)
                conn.send(create_success_packet(message=f"File ID: {current_user_id}:{filename}"))
                operations.logs.add_user_entry(current_user_id, filename, True,  file_id=file_id)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, filename, False, file_id=file_id)

        case PacketType.LIST.value:
            response_payload = {}
            try:
                if payload.get("owned"):
                    command = "list -o"
                    response_payload["owned_files"]  = operations.list_user_owned_files(current_user_id)
                elif user_id := payload.get("user_id"):
                    command = f"list -u {user_id}"
                    response_payload["shared_files"] = operations.list_user_shared_files(current_user_id, user_id)
                elif group_id := payload.get("group_id"):
                    command = f"list -g {group_id}"
                    response_payload["group_files"]  = operations.list_user_group_files(current_user_id, group_id)
                elif not payload:
                    command = "list"
                    response_payload["owned_files"]  = operations.list_user_owned_files(current_user_id)
                    response_payload["shared_files"] = operations.list_all_user_shared_files(current_user_id)
                    response_payload["group_files"]  = operations.list_all_user_group_files(current_user_id)

                conn.send(create_packet(PacketType.LIST.value, response_payload))
                operations.logs.add_user_entry(current_user_id, command, True)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, command, False)

        case PacketType.SHARE.value:
            file_id     = payload.get("file_id")
            user_id     = payload.get("user_id")
            permissions = payload.get("permissions")
            try:
                public_key, file_key = operations.init_share_user_file(current_user_id, file_id, user_id, permissions)
                intermediate_packet = create_packet(PacketType.SHARE.value,
                                                    {"public_key": base64.b64decode(public_key),
                                                     "file_symmetric_key": base64.b64decode(file_key)})
                conn.send(intermediate_packet)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"share {file_id} {user_id} {permissions}", False,
                                               file_id=file_id)
                return

            try:
                # Await client response with encrypted file key
                client_response_packet = receive_packet(conn)

                file_key = client_response_packet.get("payload").get("key")
                file_key = base64.b64encode(file_key).decode("utf-8")
                operations.share_user_file(current_user_id, file_id, user_id, permissions, file_key)

                conn.send(create_success_packet())
                operations.logs.add_user_entry(current_user_id, f"share {file_id} {user_id} {permissions}", True,
                                               file_id=file_id)
                operations.logs.add_user_entry(user_id, f"share {file_id} {user_id} {permissions}", True,
                                               file_id=file_id, executor_id=current_user_id)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"share {file_id} {user_id} {permissions}", False,
                                               file_id=file_id)

        # TODO users that had access via share or group don't have the log entry
        case PacketType.DELETE.value:
            file_id = payload.get("file_id")
            try:
                operations.delete_file(current_user_id, file_id)
                conn.send(create_success_packet())
                operations.logs.add_user_entry(current_user_id, f"delete {file_id}", True, file_id=file_id)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"delete {file_id}", False, file_id=file_id)

        # TODO users that have access via share or group don't have the log entry
        case PacketType.REPLACE.value:
            file_id = payload.get("file_id")
            try:
                file_key = operations.init_replace_file(current_user_id, file_id)
                intermediate_packet = create_packet(PacketType.REPLACE.value,
                                                    {"key": base64.b64decode(file_key)})
                conn.send(intermediate_packet)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"replace {file_id}", False, file_id=file_id)
                return

            try:
                # Await client response with encrypted new file content
                client_response_packet = receive_packet(conn)

                new_content = client_response_packet.get("payload").get("content")
                new_size = client_response_packet.get("payload").get("size")

                operations.replace_file(current_user_id, file_id, new_content, new_size)
                conn.send(create_success_packet())
                operations.logs.add_user_entry(current_user_id, f"replace {file_id}", True, file_id=file_id)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"replace {file_id}", False, file_id=file_id)

        case PacketType.DETAILS.value:
            file_id = payload.get("file_id")
            try:
                details = operations.file_details(current_user_id, file_id)
                conn.send(create_packet(PacketType.DETAILS.value, details))
                operations.logs.add_user_entry(current_user_id, f"details {file_id}", True, file_id=file_id)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"details {file_id}", False, file_id=file_id)

        case PacketType.REVOKE.value:
            file_id = payload.get("file_id")
            user_id = payload.get("user_id")
            try:
                operations.revoke_user_file_permissions(current_user_id, file_id, user_id)
                conn.send(create_success_packet())
                operations.logs.add_user_entry(current_user_id, f"revoke {file_id} {user_id}", True,
                                               file_id=file_id)
                operations.logs.add_user_entry(user_id, f"revoke {file_id} {user_id}", True,
                                               file_id=file_id, executor_id=current_user_id)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"revoke {file_id} {user_id}", False,
                                               file_id=file_id)

        case PacketType.READ.value:
            try:
                file_id = payload.get("file_id")
                file = operations.read_file(current_user_id, file_id)

                file_content = file.get("file_contents")
                file_key = base64.b64decode(file.get("key"))

                conn.send(create_packet(PacketType.READ.value,
                                        {"content": file_content,
                                         "key": file_key}))
                operations.logs.add_user_entry(current_user_id, f"read {file_id}", True, file_id=file_id)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"read {file_id}", False, file_id=file_id)

        case PacketType.GROUP_CREATE.value:
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

        case PacketType.GROUP_DELETE.value:
            group_id = payload.get("id")
            try:
                operations.delete_group(current_user_id, group_id)
                conn.send(create_success_packet())
                operations.logs.add_user_entry(current_user_id, f"group delete {group_id}", True, group_id=group_id)
                operations.logs.add_group_entry(current_user_id, group_id, f"group delete {group_id}", True)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"group delete {group_id}", False, group_id=group_id)

        case PacketType.GROUP_ADD_USER_INIT.value:
            group_id = payload.get("group_id")
            user_id  = payload.get("user_id")
            try:
                group_key, user_public_key = operations.init_add_user_to_group(current_user_id, group_id, user_id)
                server_response = create_packet(PacketType.GROUP_ADD_USER_INIT.value,
                                                {"group_key": base64.b64decode(group_key),
                                                 "public_key": base64.b64decode(user_public_key)})
                conn.send(server_response)
            except Exception as e:
                conn.send(create_error_packet(str(e)))

        case PacketType.GROUP_ADD_USER.value:
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

        case PacketType.GROUP_DELETE_USER.value:
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
                if client_response.get("type") == PacketType.CONFIRM.value:
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

        case PacketType.GROUP_LIST.value:
            try:
                groups = operations.list_user_groups(current_user_id)
                conn.send(create_packet(PacketType.GROUP_LIST.value, {"groups": groups}))
                operations.logs.add_user_entry(current_user_id, "group list", True)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, "group list", False)

        case PacketType.GROUP_ADD_INIT.value:
            group_id = payload.get("group_id")
            filename = payload.get("filename")
            size     = payload.get("size")
            try:
                group_key = operations.init_add_file_to_group(current_user_id, group_id, filename, size)
                server_response = create_packet(PacketType.GROUP_ADD_INIT.value,
                                                {"group_key": base64.b64decode(group_key)})
                conn.send(server_response)
            except Exception as e:
                conn.send(create_error_packet(str(e)))

        case PacketType.GROUP_ADD.value:
            group_id  = payload.get("group_id")
            content   = payload.get("content")
            filename  = payload.get("filename")
            size      = payload.get("size")
            group_key = payload.get("group_key")
            try:
                group_key = base64.b64encode(group_key).decode("utf-8")
                file_id = operations.add_file_to_group(current_user_id, group_id, filename, content, size, group_key)
                conn.send(create_success_packet(message=f"File ID: {file_id}"))
                operations.logs.add_user_entry(current_user_id, f"group add {group_id} {filename}", True,
                                               group_id=group_id)
                operations.logs.add_group_entry(current_user_id, group_id, f"group add {group_id} {filename}", True)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"group add {group_id} {filename}", False,
                                               group_id=group_id)

        case PacketType.GROUP_DELETE_FILE.value:
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

        case PacketType.GROUP_CHANGE_PERMISSIONS.value:
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

        case PacketType.GROUP_ADD_MODERATOR.value:
            user_id = payload.get("user_id")
            group_id = payload.get("group_id")
            try:
                user_group_key, user_pub_key = operations.init_add_moderator_to_group(current_user_id, group_id, user_id)
                user_group_key = base64.b64decode(user_group_key)
                user_pub_key   = base64.b64decode(user_pub_key)

                response = create_packet(PacketType.GROUP_ADD_MODERATOR.value,
                                         {"group_key": user_group_key,
                                          "public_key": user_pub_key})
                conn.send(response)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"group add-moderator {group_id} {user_id}", False,
                                               group_id=group_id)

            try:
                # Await client response with group key encrypted with user public key
                client_response_packet = receive_packet(conn)

                group_key = base64.b64encode(client_response_packet.get("payload").get("key")).decode("utf-8")
                operations.add_moderator_to_group(current_user_id, group_id, user_id, group_key)
                conn.send(create_success_packet())
                operations.logs.add_user_entry(current_user_id, f"group add-moderator {group_id} {user_id}", True,
                                               group_id=group_id)
                operations.logs.add_group_entry(current_user_id, group_id, f"group add-moderator {group_id} {user_id}", True)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"group add-moderator {group_id} {user_id}", False,
                                               group_id=group_id)

        case PacketType.GROUP_REMOVE_MODERATOR.value:
            group_id = payload.get("group_id")
            moderator_id = payload.get("moderator_id")
            try:
                operations.remove_moderator_from_group(current_user_id, group_id, moderator_id)
                conn.send(create_success_packet())
                operations.logs.add_user_entry(current_user_id, f"group remove-moderator {group_id} {moderator_id}", True,
                                               group_id=group_id)
                operations.logs.add_group_entry(current_user_id, group_id, f"group remove-moderator {group_id} {moderator_id}", True)
            except Exception as e:
                conn.send(create_error_packet(str(e)))
                operations.logs.add_user_entry(current_user_id, f"group remove-moderator {group_id} {moderator_id}", False,
                                               group_id=group_id)

        case PacketType.LOGS_GLOBAL.value:
            try:
                logs = operations.list_user_logs(current_user_id)
                conn.send(create_packet(PacketType.LOGS_GLOBAL.value,
                                        {"logs": logs}))
            except Exception as e:
                conn.send(create_error_packet(str(e)))

        case PacketType.LOGS_GROUP_OWNER.value:
            try:
                group_id = payload.get("group_id")
                logs = operations.list_group_logs(current_user_id, group_id)
                conn.send(create_packet(PacketType.LOGS_GROUP_OWNER.value,
                                        {"logs": logs}))
            except Exception as e:
                conn.send(create_error_packet(str(e)))

        case PacketType.LOGS_FILE.value:
            try:
                file_id = payload.get("file_id")
                logs = operations.list_user_file_logs(current_user_id, file_id)
                conn.send(create_packet(PacketType.LOGS_FILE.value,
                                        {"logs": logs}))
            except Exception as e:
                conn.send(create_error_packet(str(e)))

        case PacketType.LOGS_GROUP.value:
            try:
                group_id = payload.get("group_id")
                logs = operations.list_user_group_logs(current_user_id, group_id)
                conn.send(create_packet(PacketType.LOGS_GROUP.value,
                                        {"logs": logs}))
            except Exception as e:
                conn.send(create_error_packet(str(e)))
