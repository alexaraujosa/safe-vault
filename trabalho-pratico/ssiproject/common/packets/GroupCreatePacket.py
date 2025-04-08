import io
import ssl
from .BasePacket import BasePacket, PacketKind

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - GROUP_NAME_LEN: 4 bytes
#   - GROUP_NAME: GROUP_NAME_LEN bytes
#
class GroupCreatePacket(BasePacket):
    def __init__(self, groupName: str):
        super().__init__()
        self.kind = PacketKind.GROUP_CREATE

        self.groupName = groupName

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        self.writeString(s, self.groupName)

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        groupName = cls.readString(s)

        return cls(groupName).setOperationId(phead["operationId"])