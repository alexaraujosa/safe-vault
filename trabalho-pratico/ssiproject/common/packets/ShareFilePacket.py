import io
import ssl
from .BasePacket import BasePacket, PacketKind

class SharePermType(Enum):
    READ  = 0
    WRITE = 1
    RW    = 2

    def to_bytes(self, bytelen, encoding):
        return (int)(self._value_).to_bytes(bytelen, encoding)

    @classmethod
    def from_bytes(cls, bytes, encoding):
        return cls(int.from_bytes(bytes, encoding))

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - FILE_ID_LEN: 4 bytes
#   - FILE_ID_CONTENT: ID_LEN bytes
#   - USER_ID_LEN: 4 bytes
#   - USER_ID_CONTENT: ID_LEN bytes
#   - PERM: 1 bytes
#
class ShareFilePacket(BasePacket):
    PERM_BYTELEN = 1

    def __init__(self, fileId: str, userId: str, perm: SharePermType):
        super().__init__(operationId)
        self.kind = PacketKind.LIST_FILES

        self.fileId = fileId
        self.userId = userId
        self.perm = perm

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        self.writeString(s, self.fileId)
        self.writeString(s, self.userId)
        s.write(self.perm.to_bytes(self.PERM_BYTELEN, "little"))

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        fileId = cls.readString(s)
        userId = cls.readString(s)
        perm = SharePermType.from_bytes(cls.readTotallyOrFail(s, cls.PERM_BYTELEN, "perm"), "little")

        return cls(fileId, userId, perm).setOperationId(phead["operationId"])