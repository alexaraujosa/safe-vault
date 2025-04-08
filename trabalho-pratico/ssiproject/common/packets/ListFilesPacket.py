import io
import ssl
from .BasePacket import BasePacket, PacketKind

# TODO: Add response packet. Too tired to process how to organize it right now.

class ListQueryType(Enum):
    USER  = 0
    GROUP = 1

    def to_bytes(self, bytelen, encoding):
        return (int)(self._value_).to_bytes(bytelen, encoding)

    @classmethod
    def from_bytes(cls, bytes, encoding):
        return cls(int.from_bytes(bytes, encoding))

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - ID_LEN: 4 bytes
#   - ID_CONTENT: ID_LEN bytes
#   - QTYPE: 1 bytes
#
class ListFilePacket(BasePacket):
    QTYPE_BYTELEN = 1

    def __init__(self, pid: str, qtype: ListQueryType):
        super().__init__(operationId)
        self.kind = PacketKind.LIST_FILES

        self.id = pid
        self.qtype = qtype

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        self.writeString(s, self.pid)
        s.write(self.qtype.to_bytes(self.QTYPE_BYTELEN, "little"))

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        pid = cls.readString(s)
        queryType = ListQueryType.from_bytes(cls.readTotallyOrFail(s, cls.QTYPE_BYTELEN, "queryType"), "little")

        return cls(pid, queryType).setOperationId(phead["operationId"])