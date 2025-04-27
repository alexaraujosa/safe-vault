import ssl
from server.operations import Operations
from common.packet import (
    CommandType,
    # create_packet,
    create_success_packet,
    create_error_packet,
    decode_packet
)


def process_request(operations: Operations, current_user_id: str, conn: ssl.SSLSocket, packet_data: bytes):
    try:
        packet = decode_packet(packet_data)
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
                try:
                    group_name = packet.get("name")
                    group_key  = packet.get("key")
                    group_id = operations.create_group(current_user_id, group_name, group_key)
                    response = create_success_packet(group_id)
                except Exception as e:
                    response = create_error_packet(str(e))
                finally:
                    conn.send(response)

            case CommandType.GROUP_DELETE_REQUEST.value:
                # TODO group delete
                pass
            case CommandType.GROUP_ADD_USER_REQUEST.value:
                # TODO group add-user
                pass
            case CommandType.GROUP_DELETE_USER_REQUEST.value:
                # TODO group delete-user
                pass
            case CommandType.GROUP_LIST_REQUEST.value:
                # TODO group list
                pass
            case CommandType.GROUP_ADD_REQUEST.value:
                # TODO group add
                pass
            case CommandType.EXIT_REQUEST.value:
                # TODO exit
                pass

    except Exception as e:
        print(e)
