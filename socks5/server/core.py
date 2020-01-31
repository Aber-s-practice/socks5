import signal
import asyncio
import logging
from socket import AF_INET, AF_INET6, inet_ntop
from typing import Tuple

from socks5.values import Status, Command, Atyp
from socks5.types import Socket
from socks5.utils import TCPSocket


from ._socks5 import create_replication
from .exceptions import (
    Socks5Error,
    NoVersionAllowed,
    NoCommandAllowed,
    NoATYPAllowed,
    AuthenticationError,
    NoAuthenticationAllowed,
)
from .authentications import BaseAuthentication, NoAuthentication
from .sessions import ConnectSession, BindSession, UDPSession

logger: logging.Logger = logging.getLogger("Socks5")


class Socks5:
    """A socks5 server"""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 1080,
        *,
        authentication_class: BaseAuthentication = NoAuthentication,
        connect_session_class: ConnectSession = ConnectSession,
        bind_session_class: BindSession = BindSession,
        udp_session_class: UDPSession = UDPSession,
    ):
        self.host = host
        self.port = port

        self.authentication_class = authentication_class
        self.connect_session_class = connect_session_class
        self.bind_session_class = bind_session_class
        self.udp_session_class = udp_session_class

    async def link(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        deal all link
        """
        try:
            socket = TCPSocket(reader, writer)
            logger.debug(f"Connection from {writer.get_extra_info('peername')}")
            command, host, port = await self.shake_hand(socket)
        except AuthenticationError as e:
            logger.warning(e)
            await socket.close()
            return
        except (Socks5Error, ConnectionError):
            await socket.close()
            return

        try:
            if command == Command.CONNECT:
                await self.connect_session_class(socket, host, port).run()
            elif command == Command.UDP_ASSOCIATE:
                await self.udp_session_class(socket, host, port).run()
            elif command == Command.BIND:
                await self.bind_session_class(socket, host, port).run()
        finally:
            await socket.close()

    async def shake_hand(self, sock: Socket) -> Tuple[int, str, int]:
        data = await sock.recv(2)
        VER, NMETHODS = data
        if VER != 5:
            await sock.send(b"\x05\xff")
            raise NoVersionAllowed("Unsupported version!")

        # authenticate
        authentication = self.authentication_class(sock)
        METHODS = set(await sock.recv(NMETHODS))
        METHOD = authentication.get_method(METHODS)
        await sock.send(b"\x05" + METHOD.to_bytes(1, "big"))
        if METHOD == 255:
            raise NoAuthenticationAllowed("No authentication methods available")
        await authentication.authenticate()

        data = await sock.recv(4)
        VER, CMD, RSV, ATYP = data
        if VER != 5:
            await sock.send(create_replication(Status.GENERAL_SOCKS_SERVER_FAILURE))
            raise NoVersionAllowed("Unsupported version!")

        # Parse target address
        if ATYP == Atyp.IPV4:
            ipv4 = await sock.recv(4)
            DST_ADDR = inet_ntop(AF_INET, ipv4)
        elif ATYP == Atyp.DOMAIN:
            addr_len = int.from_bytes(await sock.recv(1), byteorder="big")
            DST_ADDR = (await sock.recv(addr_len)).decode()
        elif ATYP == Atyp.IPV6:
            ipv6 = await sock.recv(16)
            DST_ADDR = inet_ntop(AF_INET6, ipv6)
        else:
            await sock.send(create_replication(Status.ADDRESS_TYPE_NOT_SUPPORTED))
            raise NoATYPAllowed(f"Unsupported ATYP value: {ATYP}")

        DST_PORT = int.from_bytes(await sock.recv(2), "big")

        # judge command
        if CMD not in (Command.CONNECT, Command.BIND, Command.UDP_ASSOCIATE):
            await sock.send(create_replication(Status.COMMAND_NOT_SUPPORTED))
            raise NoCommandAllowed(f"Unsupported CMD value: {CMD}")
        return CMD, DST_ADDR, DST_PORT

    async def start(self) -> asyncio.AbstractServer:
        return await asyncio.start_server(self.link, self.host, self.port)

    async def run_forever(self) -> None:
        """
        run server forever
        """
        server = await self.start()
        logger.info(f"Using {asyncio.get_event_loop().__class__.__name__}")
        logger.info(f"Socks5 Server serving on {server.sockets[0].getsockname()}")

        def termina(signo, frame):
            server.close()
            logger.info(f"Socks5 Server has closed.")

        signal.signal(signal.SIGINT, termina)
        signal.signal(signal.SIGTERM, termina)

        while server.is_serving():
            await asyncio.sleep(1)

    def run(self) -> None:
        asyncio.get_event_loop().run_until_complete(self.run_forever())
