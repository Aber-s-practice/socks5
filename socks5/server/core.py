import signal
import asyncio
import logging
import traceback
from random import randint
from socket import AF_INET, AF_INET6, inet_ntop, inet_pton
from typing import Any, Tuple, Callable

from socks5.values import Status, Command, Atyp
from socks5.types import Socket, AddressType
from socks5.utils import onlyfirst, judge_atyp

from .exceptions import (
    Socks5Error,
    NoVersionAllowed,
    NoCommandAllowed,
    NoATYPAllowed,
    AuthenticationError,
    NoAuthenticationAllowed,
)
from .authentications import BaseAuthentication, NoAuthentication

from . import create_replication

logger: logging.Logger = logging.getLogger("Socks5")


class TCPSocket(Socket):
    """
    wrapper asyncio.StreamReader, asyncio.StreamWriter
    """

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.r = reader
        self.w = writer
        self.__address = writer.get_extra_info("peername")

    @property
    def address(self) -> AddressType:
        return self.__address

    async def recv(self, num: int) -> bytes:
        data = await self.r.read(num)
        return data

    async def send(self, data: bytes) -> int:
        self.w.write(data)
        await self.w.drain()
        return len(data)

    @property
    def closed(self) -> bool:
        return self.w.is_closing()

    async def close(self) -> None:
        if self.closed:
            return
        self.w.close()


class BaseSession:
    def __init__(self, sock: TCPSocket, host: str, port: int) -> None:
        self.sock = sock
        self.host = host
        self.port = port

    async def run(self) -> None:
        await self.sock.send(create_replication(Status.COMMAND_NOT_SUPPORTED))


class ConnectSession(BaseSession):
    """
    CONNECT Session
    """

    async def connect_remote(self, host: str, port: int) -> Socket:
        """
        connect remote and return Socket
        """
        r, w = await asyncio.open_connection(host, port)
        return TCPSocket(r, w)

    async def bridge(self, sender: Socket, receiver: Socket) -> None:
        while True:
            data = await sender.recv(8192)
            if not data:
                return
            await receiver.send(data)

    async def run(self) -> None:
        local, host, port = self.sock, self.host, self.port

        try:
            logger.debug(f"Connecting {host}:{port}")
            remote = await self.connect_remote(host, port)
            logger.info(f"Connected {host}:{port}")
        except ConnectionRefusedError:
            await local.send(create_replication(Status.CONNECTION_REFUSED))
            logger.info(f"Failing connect {host}:{port}")
        except (ConnectionError, TimeoutError, asyncio.TimeoutError):
            await local.send(create_replication(Status.GENERAL_SOCKS_SERVER_FAILURE))
        except Exception:
            await local.send(create_replication(Status.GENERAL_SOCKS_SERVER_FAILURE))
            logger.error("Unknown Error: ↓↓↓")
            traceback.print_exc()
        else:
            await local.send(create_replication(Status.SUCCEEDED))
            try:
                await onlyfirst(self.bridge(remote, local), self.bridge(local, remote))
            finally:
                await remote.close()
                await local.close()


class BindSession(BaseSession):
    """
    BIND Session
    """


class UDPSession(BaseSession):
    """
    UDP ASSOCIATE Session
    """

    def generate_message(
        self, message: bytes, address: AddressType
    ) -> Tuple[bytes, AddressType]:
        """
        create message that send udp to remote

        notice: `address` is the destination address to which the message is sent.
        """
        return message, address

    def parse_message(
        self, message: bytes, address: AddressType
    ) -> Tuple[bytes, AddressType]:
        """
        parse message from remote

        notice: `address` is the source address of the message.
        """
        return message, address

    class Protocol:
        def __init__(
            self,
            local_address: AddressType,
            generate_message: Callable[[bytes, AddressType], Tuple[bytes, AddressType]],
            parse_message: Callable[[bytes, AddressType], Tuple[bytes, AddressType]],
        ) -> None:
            self.local_address = local_address
            self.generate_message = generate_message
            self.parse_message = parse_message

        def local_is_zero(self) -> bool:
            """
            return self.local_address in (
                ("0.0.0.0", 0), ("::", 0)
            )
            """
            return self.local_address in (("0.0.0.0", 0), ("::", 0))

        def connection_made(self, transport: asyncio.DatagramTransport) -> None:
            self.transport = transport

        def connection_lost(self, exc) -> None:
            pass

        def parse_socks5_header(self, data) -> Tuple[bytes, AddressType]:
            _data = bytearray(data)

            def recv(num: int) -> bytes:
                if num == -1:
                    return bytes(_data)
                r = _data[:num]
                del _data[:num]
                return bytes(r)

            _ = recv(2)  # RSV
            FRAG = recv(1)
            if int.from_bytes(FRAG, "big") != 0:
                return None
            ATYP = int.from_bytes(recv(1), "big")
            # Parse target address
            if ATYP == Atyp.IPV4:
                ipv4 = recv(4)
                DST_ADDR = inet_ntop(AF_INET, ipv4)
            elif ATYP == Atyp.DOMAIN:
                addr_len = int.from_bytes(recv(1), byteorder="big")
                DST_ADDR = (recv(addr_len)).decode()
            elif ATYP == Atyp.IPV6:
                ipv6 = recv(16)
                DST_ADDR = inet_ntop(AF_INET6, ipv6)
            else:
                raise AssertionError()
            DST_PORT = int.from_bytes(recv(2), "big")
            return recv(-1), (DST_ADDR, DST_PORT)

        def add_socks5_header(self, data: bytes, address: AddressType) -> bytes:
            RSV, FRAG = b"\x00\x00", b"\x00"
            ATYP = judge_atyp(address[0])
            if ATYP == Atyp.IPV4:
                DST_ADDR = inet_pton(AF_INET, address[0])
            elif ATYP == Atyp.IPV6:
                DST_ADDR = inet_pton(AF_INET6, address[0])
            elif ATYP == Atyp.DOMAIN:
                DST_ADDR = len(address[0]).to_bytes(2, "big") + address[0].encode(
                    "UTF-8"
                )
            ATYP = ATYP.to_bytes(1, "big")
            DST_PORT = address[1].to_bytes(2, "big")
            return RSV + FRAG + ATYP + DST_ADDR + DST_PORT + data

        def datagram_received(self, data: bytes, address: AddressType) -> None:
            if self.local_is_zero() or address == self.local_address:
                # parse socks5
                try:
                    message, target = self.parse_socks5_header(data)
                except AssertionError:
                    return

                if self.local_is_zero():
                    self.local_address = address

                self.transport.sendto(*self.generate_message(message, target))
            else:
                self.transport.sendto(
                    self.add_socks5_header(*self.parse_message(message, address)),
                    self.local_address,
                )

    async def heartbeat(self) -> None:
        try:
            while True:
                await asyncio.sleep(5)
                await self.sock.send(b"heartbeat")
        except ConnectionResetError:
            pass

    async def create_udp_server(
        self, max_time: int = 3
    ) -> Tuple[asyncio.DatagramTransport, Any]:
        host = self.sock.address[0]

        for _ in range(max_time):
            try:
                port = randint(1025, 65535)
                return await asyncio.get_event_loop().create_datagram_endpoint(
                    lambda: self.Protocol(
                        (self.host, self.port),
                        self.generate_message,
                        self.parse_message,
                    ),
                    (host, port),
                )
            except OSError:  # can't bind address
                pass

    async def run(self) -> None:
        try:
            transport, protocol = await self.create_udp_server(3)
            await self.sock.send(create_replication(Status.SUCCEEDED))
        except OSError:
            await self.sock.send(
                create_replication(Status.GENERAL_SOCKS_SERVER_FAILURE)
            )

        asyncio.get_event_loop().create_task(self.heartbeat())

        while not self.sock.closed:
            await asyncio.sleep(1)

        transport.close()


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

    def close(self) -> None:
        self.server.close()
        logger.info(f"Socks5 Server has closed.")

    async def link(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        deal all link
        """
        socket = TCPSocket(reader, writer)
        logger.debug(f"Connection from {writer.get_extra_info('peername')}")
        try:
            command, host, port = await self.shake_hand(socket)

            if command == Command.CONNECT:
                await self.connect_session_class(socket, host, port).run()
            elif command == Command.UDP_ASSOCIATE:
                await self.udp_session_class(socket, host, port).run()
            elif command == Command.BIND:
                await self.bind_session_class(socket, host, port).run()

        except AuthenticationError as e:
            logger.warning(e)
        except ValueError:  # unpack error
            pass
        except (Socks5Error, ConnectionError):
            pass

        await socket.close()

    async def shake_hand(self, sock: TCPSocket) -> Tuple[int, str, int]:
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
        logger.info(f"Socks5 Server serving on {server.sockets[0].getsockname()}")

        def termina(signo, frame):
            server.close()

        signal.signal(signal.SIGINT, termina)
        signal.signal(signal.SIGTERM, termina)

        while server.is_serving():
            await asyncio.sleep(1)

    def run(self) -> None:
        asyncio.get_event_loop().run_until_complete(self.run_forever())
