import io
import ssl
from .BasePacket import BasePacket, PacketKind

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - GROUP_ID_LEN: 4 bytes
#   - GROUP_ID: GROUP_ID_LEN bytes
#   - USER_ID_LEN: 4 bytes
#   - USER_ID: USER_ID_LEN bytes
#
class GroupDeleteUserPacket(BasePacket):
    def __init__(self, groupId: str, userId: str):
        super().__init__()
        self.kind = PacketKind.GROUP_DELUSER

        self.groupId = groupId
        self.userId = userId

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        self.writeString(s, self.groupId)
        self.writeString(s, self.userId)

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        groupId = cls.readString(s)
        userpId = cls.readString(s)

        return cls(groupId, user).setOperationId(phead["operationId"])