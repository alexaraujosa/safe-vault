import io
import ssl
from .BasePacket import BasePacket, PacketKind

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - FILE_ID_LEN: 4 bytes
#   - FILE_ID: FILE_ID_LEN bytes
#   - CONTENT_LEN: 4 bytes
#   - CONTENT: CONTENT_LEN bytes
#
class ReplaceFilePacket(BasePacket):
    def __init__(self, fileId: str, fileContent: bytes):
        super().__init__(operationId)
        self.kind = PacketKind.REPLACE_FILE

        self.fileId = fileId
        self.fileContent = fileContent

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        self.writeString(s, self.fileId)
        self.writeBytes(s, self.fileContent)

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        fileId = cls.readString(s)
        fileContent = cls.readBytes(s)

        return cls(fileId, fileContent).setOperationId(phead["operationId"])