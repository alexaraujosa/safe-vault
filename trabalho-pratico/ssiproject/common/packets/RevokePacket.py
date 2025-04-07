import io
import ssl
from .BasePacket import BasePacket, PacketKind

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - FILE_ID_LEN: 4 bytes
#   - FILE_ID: FILE_ID_LEN bytes
#   - USER_ID_LEN: 4 bytes
#   - USER_ID: USER_ID_LEN bytes
#
class RevokePacket(BasePacket):
    def __init__(self, fileId: str, userId: bytes):
        super().__init__(operationId)
        self.kind = PacketKind.REVOKE

        self.fileId = fileId
        self.userId = userId

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        self.writeString(s, self.fileId)
        self.writeString(s, self.userId)

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        fileId = cls.readString(s)
        userId = cls.readString(s)

        return cls(fileId, userId).setOperationId(phead["operationId"])