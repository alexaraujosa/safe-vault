import io
import ssl
from .BasePacket import BasePacket, PacketKind

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - GROUP_ID_LEN: 4 bytes
#   - GROUP_ID: GROUP_ID_LEN bytes
#
class GroupDeletePacket(BasePacket):
    def __init__(self, groupId: str):
        super().__init__()
        self.kind = PacketKind.GROUP_DELETE

        self.groupId = groupId

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        self.writeString(s, self.groupId)

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        groupId = cls.readString(s)

        return cls(groupId).setOperationId(phead["operationId"])