import io
import ssl
from .BasePacket import BasePacket, PacketKind

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#
class HelloPacket(BasePacket):
    def __init__(self):
        super().__init__()
        self.kind = PacketKind.HELLO

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)
        return s