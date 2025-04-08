import ssl
import io
from enum import Enum
from abc import abstractmethod
from ssiproject.common.exceptions.PacketDeserializationException import PacketDeserializationException

class PacketKind(Enum):
    _NULL            = 0
    DIE              = 1
    HELLO            = 2
    OP_RESULT        = 3
    ADD_FILE         = 4
    LIST_FILES       = 5
    LIST_FILES_RES   = 6
    DELETE_FILE      = 7
    REPLACE_FILE     = 8
    DETAILS_FILE     = 9
    DETAILS_FILE_RES = 10
    REVOKE           = 11
    READ_FILE        = 12
    READ_FILE_RES    = 13
    GROUP_CREATE     = 14
    GROUP_DELETE     = 15
    GROUP_ADDUSER    = 16
    GROUP_DELUSER    = 17
    GROUP_LIST       = 18
    GROUP_ADDFILE    = 19

    def to_bytes(self, bytelen, encoding):
        return (int)(self._value_).to_bytes(bytelen, encoding)

    @classmethod
    def from_bytes(cls, bytes, encoding):
        return cls(int.from_bytes(bytes, encoding))

#
# LAYOUT:
#   - SIGNATURE: 3 bytes
#   - VERSION: 1 bytes
#   - KIND: 1 byte
#   - OPERATION_ID: 2 byte
#
class BasePacket:
    SIGNATURE = "SSI"
    SIGNATURE_BYTES = bytes(SIGNATURE, "ascii")
    SIGNATURE_BYTELEN = len(SIGNATURE)

    VERSION = 0x03
    VERSION_BYTELEN = 1

    KIND_BYTELEN = 1
    OPERATION_ID_BYTELEN = 2

    def __init__(self, operationId: int = 0):
        self.kind = PacketKind._NULL
        self.operationId = operationId

    def setOperationId(self, operationId):
        self.operationId = operationId
        return self

    #region -------------- STREAM METHODS --------------
    @abstractmethod
    def serialize(self, s: io.BytesIO):
        s.write(BasePacket.SIGNATURE_BYTES)
        s.write(BasePacket.VERSION.to_bytes(BasePacket.VERSION_BYTELEN, "little"))
        s.write(self.kind.to_bytes(BasePacket.KIND_BYTELEN, "little"))
        s.write(self.operationId.to_bytes(BasePacket.OPERATION_ID_BYTELEN, "little"))

    def serializeBytes(self, s: io.BytesIO = None):
        bio = self.serialize(s)
        bio.seek(0)
        return bio.read()

    @classmethod
    @abstractmethod
    def deserialize(cls, phead, s: ssl.SSLSocket):
        return cls.readHeader(s)
    #endregion -------------- STREAM METHODS --------------

    #region -------------- READ SOCKET METHODS --------------
    @classmethod
    def readHeader(cls, s: ssl.SSLSocket):
        # phead = s.read(BasePacket.SIGNATURE_BYTELEN)
        # print("BPRH:", phead)
        # if (phead != BasePacket.SIGNATURE_BYTES):
        #     raise PacketDeserializationException("<packet header>", f"Invalid signature.")

        pSigStatus = cls.readSigBytesNoFail(s)
        if (pSigStatus != 0): raise PacketDeserializationException("<packet header>", f"Invalid signature.")

        return cls.readHeaderNoSig(s)

    @classmethod
    def readSigBytesNoFail(cls, s: ssl.SSLSocket):
        phead = s.recv(cls.SIGNATURE_BYTELEN)
        if (phead == b""): return 1
        elif (phead != BasePacket.SIGNATURE_BYTES): return 2
        else: return 0
    
    @classmethod
    def readHeaderNoSig(cls, s: ssl.SSLSocket):
        version = int.from_bytes(cls.readTotallyOrFail(s, BasePacket.VERSION_BYTELEN, "version"), "little")
        if (version != BasePacket.VERSION):
            raise PacketDeserializationException("<packet header>", f"Invalid version: {version}.")

        kind = PacketKind.from_bytes(cls.readTotallyOrFail(s, BasePacket.KIND_BYTELEN, "kind"), "little")
        operationId = int.from_bytes(cls.readTotallyOrFail(s, BasePacket.OPERATION_ID_BYTELEN, "operationId"), "little")

        return {
            "kind": kind,
            "operationId": operationId
        }


    @staticmethod
    def readTotallyOrFail(s: ssl.SSLSocket, bytelen, propname):
        rbytes = s.recv(bytelen)
        if (rbytes == b""): raise PacketDeserializationException("<packet header>", f"Could not read {propname}")
        if (len(rbytes) != bytelen): 
            raise PacketDeserializationException("<packet header>", f"Reached EOF while reading {propname}")

        return rbytes

    @staticmethod
    def flushUntilNextPacket(s: ssl.SSLSocket):
        found = False
        while ((pb := s.read(1)) and pb != None):
            if (pb == BasePacket.SIGNATURE_BYTELEN[0]):
                pbRest = s.read(2)

                if (pbRest == b""): break
                elif (pbRest == BasePacket.SIGNATURE_BYTES[1:]): 
                    found = True
                    break

        return found
    #endregion -------------- READ SOCKET METHODS --------------

    #region -------------- READ STREAM METHODS --------------
    @classmethod
    def readString(cls, s: io.BytesIO):
        string_len = int.from_bytes(s.read(4), "little")
        if (string_len == 0): return None

        # return s.read(string_len).decode("utf-8")
        return cls.readTotallyOrFail(s, string_len, "stringfield").decode("utf-8")

    @classmethod
    def readBytes(cls, s: io.BytesIO):
        content_len = int.from_bytes(s.read(4), "little")
        if (content_len == 0): return None

        # return s.read(content_len)
        return cls.readTotallyOrFail(s, content_len, "bytefield")
    #endregion -------------- READ STREAM METHODS --------------

    #region -------------- WRITE STREAM METHODS --------------
    def writeString(self, s: io.BytesIO, string: str):
        if (string == None): 
            s.write(0x0.to_bytes(4, "little"))
            return

        s.write(len(string).to_bytes(4, "little"))
        s.write(bytes(string, "utf-8"))

    def writeBytes(self, s: io.BytesIO, content: bytes):
        if (content == None): 
            s.write(0x0.to_bytes(4, "little"))
            return

        s.write(len(content).to_bytes(4, "little"))
        s.write(content)
    #endregion -------------- WRITE STREAM METHODS --------------