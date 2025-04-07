import io
import ssl
from .BasePacket import BasePacket, PacketKind
from .ShareFilePacket import SharePermType

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - GROUP_ID_LEN: 4 bytes
#   - GROUP_ID: GROUP_ID_LEN bytes
#   - FILE_NAME_LEN: 4 bytes
#   - FILE_NAME: FILE_NAME_LEN bytes
#   - FILE_CONTENT_LEN: 4 bytes
#   - FILE_CONTENT: FILE_CONTENT_LEN bytes
#
class GroupAddFilePacket(BasePacket):
    PERM_BYTELEN = 1

    def __init__(self, groupId: str, filePath: str, fileContent: bytes):
        super().__init__()
        self.kind = PacketKind.GROUP_ADDFILE

        self.groupId = groupId
        self.userId = userId
        self.perm = perm

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        self.writeString(s, self.groupId)

        fileName = os.path.basename(self.filePath)
        self.writeString(s, fileName)
        self.writeString(s, self.fileContent)

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        groupId = cls.readString(s)
        fileName = cls.readString(s)
        fileContent = cls.readBytes(s)

        return cls(groupId, fileName, fileContent).setOperationId(phead["operationId"])