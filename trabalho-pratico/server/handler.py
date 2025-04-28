import ssl
import json
from server.operations import Operations
from common.exceptions import NeedConfirmation
from common.packet import (
    CommandType,
    # create_packet,
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
                # TODO add
                pass
            case CommandType.LIST_REQUEST.value:
                # TODO list
                pass
            case CommandType.SHARE_REQUEST.value:
                # TODO share
                pass
            case CommandType.DELETE_REQUEST.value:
                # TODO delete
                pass
            case CommandType.REPLACE_REQUEST.value:
                # TODO replace
                pass
            case CommandType.DETAILS_REQUEST.value:
                # TODO details
                pass
            case CommandType.REVOKE_REQUEST.value:
                # TODO revoke
                pass
            case CommandType.READ_REQUEST.value:
                # TODO read
                pass
            case CommandType.GROUP_CREATE_REQUEST.value:
                group_name = payload.get("name")
                group_key  = payload.get("key")
                try:
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

            case CommandType.GROUP_ADD_USER_REQUEST.value:
                # TODO group add-user
                pass
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
            case CommandType.GROUP_ADD_REQUEST.value:
                # TODO group add
                pass
            case CommandType.GROUP_DELETE_FILE_REQUEST.value:
                # TODO group delete-file
                pass

            case CommandType.EXIT_REQUEST.value:
                # TODO exit
                pass

    except Exception as e:
        print(e)
