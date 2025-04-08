import io
import ssl
from .BasePacket import BasePacket, PacketKind

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - FILENAME_LEN: 4 bytes
#   - FILENAME: FILENAME_LEN bytes
#   - CONTENT_LEN: 4 bytes
#   - CONTENT: CONTENT_LEN bytes
#
class AddFilePacket(BasePacket):
    def __init__(self, filePath: str, fileContent: bytes):
        super().__init__(operationId)
        self.kind = PacketKind.ADD_FILE

        self.filePath = filePath
        self.fileContent = fileContent

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        fileName = os.path.basename(self.filePath)
        self.writeString(s, fileName)
        self.writeString(s, self.fileContent)

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        fileName = cls.readString(s)
        fileContent = cls.readBytes(s)

        return cls(fileName, fileContent).setOperationId(phead["operationId"])