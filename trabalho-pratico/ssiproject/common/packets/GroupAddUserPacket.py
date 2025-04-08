import io
import ssl
from .BasePacket import BasePacket, PacketKind
from .ShareFilePacket import SharePermType

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - GROUP_ID_LEN: 4 bytes
#   - GROUP_ID: GROUP_ID_LEN bytes
#   - USER_ID_LEN: 4 bytes
#   - USER_ID: USER_ID_LEN bytes
#   - PERM: 1 byte
#
class GroupAddUserPacket(BasePacket):
    PERM_BYTELEN = 1

    def __init__(self, groupId: str, userId: str, perm: SharePermType):
        super().__init__()
        self.kind = PacketKind.GROUP_ADDUSER

        self.groupId = groupId
        self.userId = userId
        self.perm = perm

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        self.writeString(s, self.groupId)
        self.writeString(s, self.userId)
        s.write(self.perm.to_bytes(self.PERM_BYTELEN, "little"))

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        groupId = cls.readString(s)
        userId = cls.readString(s)
        perm = SharePermType.from_bytes(cls.readTotallyOrFail(s, cls.PERM_BYTELEN, "perm"), "little")

        return cls(groupId, userId, perm).setOperationId(phead["operationId"])