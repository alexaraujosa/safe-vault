import io
from .BasePacket import BasePacket, PacketKind

class HelloPacket(BasePacket):
    def __init__(self, body):
        super().__init__()
        self.kind = PacketKind.HELLO
        self.body = body

    def serialize(self, s: io.BytesIO):
        self.serialize()
        s.write("Hello world!")

        return s

    def deserialize(cls, s: io.BytesIO):
        return cls(s.read())