import io
import ssl
from .BasePacket import BasePacket, PacketKind

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - CONTENT_LEN: 4 bytes
#   - CONTENT: CONTENT_LEN bytes
#
class DiePacket(BasePacket):
    def __init__(self, msg: str = None):
        super().__init__()
        self.kind = PacketKind.DIE
        self.msg = msg

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        if (self.msg == None):
            s.write(0x0.to_bytes(4))
        else:
            s.write(len(self.msg).to_bytes(4, "little"))
            s.write(bytes(self.msg, "utf-8"))

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        content_len = int.from_bytes(s.read(4), "little")
        msg = s.read(content_len).decode("utf-8")

        return cls(msg).setOperationId(phead["operationId"])