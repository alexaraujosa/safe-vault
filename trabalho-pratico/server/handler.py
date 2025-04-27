import ssl

from common.packet import CommandType, decode_packet

def process_request(conn: ssl.SSLSocket, message: bytes):
    try:
        packet = decode_packet(message)
        match packet.get("type"):
            case CommandType.ADD_REQUEST:
                # TODO add
                pass
            case CommandType.LIST_REQUEST:
                # TODO list
                pass
            case CommandType.SHARE_REQUEST:
                # TODO share
                pass
            case CommandType.DELETE_REQUEST:
                # TODO delete
                pass
            case CommandType.REPLACE_REQUEST:
                # TODO replace
                pass
            case CommandType.DETAILS_REQUEST:
                # TODO details
                pass
            case CommandType.REVOKE_REQUEST:
                # TODO revoke
                pass
            case CommandType.READ_REQUEST:
                # TODO read
                pass
            case CommandType.GROUP_CREATE_REQUEST:
                # TODO group create
                pass
            case CommandType.GROUP_DELETE_REQUEST:
                # TODO group delete
                pass
            case CommandType.GROUP_ADD_USER_REQUEST:
                # TODO group add-user
                pass
            case CommandType.GROUP_DELETE_USER_REQUEST:
                # TODO group delete-user
                pass
            case CommandType.GROUP_LIST_REQUEST:
                # TODO group list 
                pass
            case CommandType.GROUP_ADD_REQUEST:
                # TODO group add
                pass
            case CommandType.EXIT_REQUEST:
                # TODO exit
                pass

    except Exception as e:
        print(e)