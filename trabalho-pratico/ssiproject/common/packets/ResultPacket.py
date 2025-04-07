import io
import ssl
from enum import Enum
from .BasePacket import BasePacket, PacketKind

class ResultType(Enum):
    SUCCESS = 0
    ERROR   = 1

    def to_bytes(self, bytelen, encoding):
        return (int)(self._value_).to_bytes(bytelen, encoding)

    @classmethod
    def from_bytes(cls, bytes, encoding):
        return cls(int.from_bytes(bytes, encoding))

#
# LAYOUT:
#   - HEADER: BasePacket bytes
#   - RESULT_TYPE: 1 byte
#   - RESULT_MSG_LEN: 4 bytes
#   - RESULT_MSG: RESULT_MSG_LEN bytes
#
class ResultPacket(BasePacket):
    RESULT_TYPE_BYTELEN = 1

    def __init__(self, resultType: ResultType, resultMsg: str = None):
        super().__init__()
        self.kind = PacketKind.OP_RESULT
        self.resultType = resultType
        self.resultMsg = resultMsg

    def serialize(self, s: io.BytesIO):
        if (s == None): s = io.BytesIO()
        super().serialize(s)

        s.write(self.resultType.to_bytes(self.RESULT_TYPE_BYTELEN, "little"))
        self.writeString(s, self.resultMsg)

        return s

    @classmethod
    def deserialize(cls, phead, s: io.BytesIO):
        resultType = ResultType.from_bytes(cls.readTotallyOrFail(s, cls.RESULT_TYPE_BYTELEN, "resultType"), "little")
        resultMsg = cls.readString(s)

        return cls(resultType, resultMsg).setOperationId(phead["operationId"])

    def format(self):
        string = "["
        if (self.resultType == ResultType.SUCCESS): string += "✅"
        else: string += "❌"
        string += f" {self.operationId}]"

        if (self.resultMsg != None): string += f" {self.resultMsg}"
        else: string += " <N/A>"

        return string