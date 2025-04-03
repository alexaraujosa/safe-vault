class PacketSerializationException(BaseException):
    def __init__(self, packetname, cause):
        super().__init__(f"Unable to serialize {packetname}: {cause}")