import io
import ssl
from .BasePacket import BasePacket, PacketKind

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - FILE_ID_LEN: 4 bytes
#   - FILE_ID: FILE_ID_LEN bytes
#
class DeleteFilePacket(BasePacket):
    def __init__(self, fileId: str):
        super().__init__()
        self.kind = PacketKind.DELETE_FILE

        self.fileId = fileId

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        self.writeString(s, self.fileId)

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        fileId = cls.readString(s)

        return cls(fileId).setOperationId(phead["operationId"])