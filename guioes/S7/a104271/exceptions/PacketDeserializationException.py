class PacketDeserializationException(BaseException):
    def __init__(self, packetname, cause):
        super().__init__(f"Unable to deserialize {packetname}: {cause}")