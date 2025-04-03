import io
import socket
from enum import Enum
from abc import abstractmethod
from exceptions.PacketDeserializationException import PacketDeserializationException

class PacketKind(Enum):
    _NULL          = 0
    HELLO          = 1
    MESSAGE        = 2
    ECDH_HANDSHAKE = 3

    def to_bytes(self, bytelen, encoding):
        return (int)(self._value_).to_bytes(bytelen, encoding)

    @classmethod
    def from_bytes(cls, bytes, encoding):
        return cls(int.from_bytes(bytes, encoding))

class BasePacket:
    SIGNATURE = "SSI"
    SIGNATURE_BYTES = bytes(SIGNATURE, "ascii")
    SIGNATURE_BYTELEN = len(SIGNATURE)

    VERSION = 0x01
    VERSION_BYTELEN = 2

    KIND_BYTELEN = 1

    def __init__(self):
        self.kind = PacketKind._NULL

    @abstractmethod
    def serialize(self, s: io.BytesIO):
        s.write(BasePacket.SIGNATURE_BYTES)
        s.write(BasePacket.VERSION.to_bytes(BasePacket.VERSION_BYTELEN, "little"))
        s.write(self.kind.to_bytes(BasePacket.KIND_BYTELEN, "little"))

    def serializeBytes(self, s: io.BytesIO = None):
        bio = self.serialize(s)
        bio.seek(0)
        return bio.read()

    @classmethod
    @abstractmethod
    def deserialize(cls, s: io.BytesIO):
        return cls.readHeader(s)

    @classmethod
    def readHeader(cls, s):
        phead = s.read(BasePacket.SIGNATURE_BYTELEN)
        if (phead != BasePacket.SIGNATURE_BYTES):
            raise PacketDeserializationException("<packet header>", f"Invalid signature.")

        return cls.readHeaderNoSig(s)
    
    @classmethod
    def readHeaderNoSig(cls, s):
        version = int.from_bytes(cls.readTotallyOrFail(s, BasePacket.VERSION_BYTELEN, "version"), "little")
        if (version != BasePacket.VERSION):
            raise PacketDeserializationException("<packet header>", f"Invalid version: {version}.")

        kind = PacketKind.from_bytes(cls.readTotallyOrFail(s, BasePacket.KIND_BYTELEN, "kind"), "little")

        return {
            "kind": kind
        }


    @staticmethod
    def readTotallyOrFail(s: io.BytesIO, bytelen, propname):
        rbytes = s.read(bytelen)
        if (rbytes == b""): raise PacketDeserializationException("<packet header>", f"Could not read {propname}")
        if (len(rbytes) != bytelen): 
            raise PacketDeserializationException("<packet header>", f"Reached EOF while reading {propname}")

        return rbytes

    @staticmethod
    def flushUntilNextPacket(s):
        found = False
        while ((pb := s.read(1)) and pb != None):
            if (pb == BasePacket.SIGNATURE_BYTELEN[0]):
                pbRest = s.read(2)

                if (pbRest == b""): break
                elif (pbRest == BasePacket.SIGNATURE_BYTES[1:]): 
                    found = True
                    break

        return found
