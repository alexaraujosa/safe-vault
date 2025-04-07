import io
import ssl
from .BasePacket import BasePacket, PacketKind

# TODO: Add response packet. Too tired to process how to organize it right now.

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - FILE_ID_LEN: 4 bytes
#   - FILE_ID: FILE_ID_LEN bytes
#
class DetailsFilePacket(BasePacket):
    def __init__(self, fileId: str):
        super().__init__()
        self.kind = PacketKind.DETAILS_FILE

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