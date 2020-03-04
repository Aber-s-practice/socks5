import signal
import asyncio
import logging
from socket import AF_INET, AF_INET6, inet_ntop
from typing import Type, NoReturn, Tuple

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
        authentication_class: Type[BaseAuthentication] = NoAuthentication,
        connect_session_class: Type[ConnectSession] = ConnectSession,
        bind_session_class: Type[BindSession] = BindSession,
        udp_session_class: Type[UDPSession] = UDPSession,
    ):
        self.host = host
        self.port = port

        self.server: asyncio.AbstractServer = None

        self.authentication_class = authentication_class
        self.connect_session_class = connect_session_class
        self.bind_session_class = bind_session_class
        self.udp_session_class = udp_session_class

    async def link(self, sock: TCPSocket) -> None:
        """
        deal all link
        """
        try:
            logger.debug(f"Connection from {sock.w.get_extra_info('peername')}")
            command, host, port = await self.shake_hand(sock)

            if command == Command.CONNECT:
                await self.connect_session_class(sock, host, port).run()
            elif command == Command.UDP_ASSOCIATE:
                await self.udp_session_class(sock, host, port).run()
            elif command == Command.BIND:
                await self.bind_session_class(sock, host, port).run()

        except AuthenticationError as e:
            logger.warning(e)
        except (Socks5Error, ConnectionError, ValueError):
            # ValueError: raise by unpack
            pass  # nothing to do
        finally:
            await sock.close()

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

    async def start_server(self) -> None:
        async def link(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            return await self.link(TCPSocket(reader, writer))

        self.server = await asyncio.start_server(link, self.host, self.port)
        await self.server.start_serving()
        logger.info(f"Using {asyncio.get_event_loop().__class__.__name__}")
        logger.info(f"Socks5 Server serving on {self.server.sockets[0].getsockname()}")

    async def stop_server(self) -> None:
        if self.server is None:
            logger.info("Server is not running.")
            return
        self.server.close()
        await self.server.wait_closed()
        logger.info("Socks5 Server has closed.")

    async def run_forever(self) -> NoReturn:
        """
        run server forever
        """
        should_exit = False

        def termina(signo, frame):
            nonlocal should_exit
            should_exit = True

        signal.signal(signal.SIGINT, termina)
        signal.signal(signal.SIGTERM, termina)

        await self.start_server()
        while not should_exit:
            await asyncio.sleep(0.25)
        await self.stop_server()

    def run(self) -> None:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.run_forever())
