from socks5.types import Socket
from .exceptions import NoVersionAllowed, AuthenticationError


class BaseAuthentication:
    def __init__(self, socket: Socket):
        self.socket = socket

    def get_method(self, methods: set) -> int:
        """
        Return a allowed authentication method or 255

        Must be overwrited.
        """
        return 255

    async def authenticate(self):
        """
        Authenticate user

        Must be overwrited.
        """
        raise AuthenticationError()


class NoAuthentication(BaseAuthentication):
    """ NO AUTHENTICATION REQUIRED """

    def get_method(self, methods: set) -> int:
        if 0 in methods:
            return 0
        return 255

    async def authenticate(self):
        pass


class PasswordAuthentication(BaseAuthentication):
    """ USERNAME/PASSWORD """

    def _authenticate(self, username: str, password: str) -> dict:
        """
        verify username and password
        """
        return username == "username" and password == "password"

    def get_method(self, methods: set) -> int:
        if 2 in methods:
            return 2
        return 255

    async def authenticate(self):
        VER = await self.socket.recv(1)
        if VER != b"\x01":
            await self.socket.send(b"\x01\x01")
            raise NoVersionAllowed("Unsupported version!")
        ULEN = int.from_bytes(await self.socket.recv(1), "big")
        UNAME = (await self.socket.recv(ULEN)).decode("ASCII")
        PLEN = int.from_bytes(await self.socket.recv(1), "big")
        PASSWD = (await self.socket.recv(PLEN)).decode("ASCII")
        if self._authenticate(UNAME, PASSWD):
            await self.socket.send(b"\x01\x00")
        else:
            await self.socket.send(b"\x01\x01")
            raise AuthenticationError("USERNAME or PASSWORD ERROR")
