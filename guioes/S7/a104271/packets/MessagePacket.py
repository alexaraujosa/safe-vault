import io
from packets.BasePacket import BasePacket, PacketKind
from pbenc_aes_gcm import enc, dec

passwd = "Sample password."

class MessagePacket(BasePacket):
    def __init__(self, msg, pkey):
        super().__init__()
        self.kind = PacketKind.MESSAGE
        self.msg = msg
        self.pkey = pkey

    def serialize(self, s: io.BytesIO = None):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        # emsg = enc(self.msg, passwd)
        emsg = enc(self.msg, self.pkey)
        s.write(emsg)
        
        return s

    @classmethod
    def deserialize(cls, s: io.BytesIO, pkey: bytes):
        # dmsg = dec(s.read(), passwd)
        dmsg = dec(s.read(), pkey)
        return cls(dmsg, pkey)