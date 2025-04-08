import io
import ssl
from .BasePacket import BasePacket, PacketKind

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - FILE_ID_LEN: 4 bytes
#   - FILE_ID: FILE_ID_LEN bytes
#
class ReadFileRequestPacket(BasePacket):
    def __init__(self, fileId: str):
        super().__init__()
        self.kind = PacketKind.READ_FILE

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

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - FILE_NAME_LEN: 4 bytes
#   - FILE_NAME: FILE_NAME_LEN bytes
#   - FILE_CONTENT_LEN: 4 bytes
#   - FILE_CONTENT: FILE_CONTENT_LEN bytes
#
class ReadFileResponsePacket(BasePacket):
    def __init__(self, fileName: str, fileContent: bytes):
        super().__init__()
        self.kind = PacketKind.READ_FILE_RES

        self.fileName = fileName
        self.fileContent = fileContent

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        self.writeString(s, self.fileName)
        self.writeBytes(s, self.fileContent)

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        fileName = cls.readString(s)
        fileContent = cls.readBytes(s)

        return cls(fileName, fileContent).setOperationId(phead["operationId"])