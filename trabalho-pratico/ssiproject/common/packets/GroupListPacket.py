import io
import ssl
from .BasePacket import BasePacket, PacketKind

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#
class GroupListPacket(BasePacket):
    def __init__(self, groupId: str):
        super().__init__()
        self.kind = PacketKind.GROUP_LIST

        self.groupId = groupId

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        pass