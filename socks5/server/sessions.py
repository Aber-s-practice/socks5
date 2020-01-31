import socket
import asyncio
import logging
import traceback
from random import randint
from typing import Tuple, Any, Callable
from socket import AF_INET, AF_INET6, inet_ntop, inet_pton

from socks5.types import Socket, AddressType
from socks5.values import Status, Atyp
from socks5.utils import judge_atyp, onlyfirst, TCPSocket

from ._socks5 import create_replication

logger: logging.Logger = logging.getLogger("Socks5")


class BaseSession:
    def __init__(self, sock: Socket, host: str, port: int) -> None:
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
            logger.debug(f"Connected {host}:{port}")
        except ConnectionRefusedError:
            await local.send(create_replication(Status.CONNECTION_REFUSED))
            logger.debug(f"ConnectionRefused {host}:{port}")
        except (ConnectionError, TimeoutError, asyncio.TimeoutError, socket.timeout):
            await local.send(create_replication(Status.GENERAL_SOCKS_SERVER_FAILURE))
            logger.debug(f"Failing connect {host}:{port}")
        except socket.gaierror:
            await local.send(create_replication(Status.HOST_UNREACHABLE))
            logger.debug(f"Failing connect {host}:{port}")
        except Exception:
            await local.send(create_replication(Status.GENERAL_SOCKS_SERVER_FAILURE))
            logger.error("Unknown Error: ↓↓↓")
            traceback.print_exc()
        else:
            try:
                await local.send(create_replication(Status.SUCCEEDED))
                await onlyfirst(self.bridge(remote, local), self.bridge(local, remote))
            finally:
                await remote.close()


class BindSession(BaseSession):
    """
    BIND Session
    """


class UDPProtocol:
    """
    Socks5 UDP Server Protocol
    """

    def __init__(
        self,
        local_address: AddressType,
        from_local: Callable[[bytes, AddressType], Tuple[bytes, AddressType]],
        from_remote: Callable[[bytes, AddressType], Tuple[bytes, AddressType]],
    ) -> None:
        self.local_address = local_address
        self.from_local = from_local
        self.from_remote = from_remote

    def local_is_zero(self) -> bool:
        """
        return self.local_address in (
            ("0.0.0.0", 0), ("::", 0)
        )
        """
        return self.local_address in (("0.0.0.0", 0), ("::", 0))

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """
        udp open
        """
        self.transport = transport

    def connection_lost(self, exc) -> None:
        """
        udp closed
        """
        # nothing to do

    def parse_socks5_header(self, data) -> Tuple[bytes, AddressType]:
        """
        parse target address and message from socks5 udp
        """
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
        """
        add socks5 header to send udp
        """
        RSV, FRAG = b"\x00\x00", b"\x00"
        ATYP = judge_atyp(address[0])
        if ATYP == Atyp.IPV4:
            DST_ADDR = inet_pton(AF_INET, address[0])
        elif ATYP == Atyp.IPV6:
            DST_ADDR = inet_pton(AF_INET6, address[0])
        elif ATYP == Atyp.DOMAIN:
            DST_ADDR = len(address[0]).to_bytes(2, "big") + address[0].encode("UTF-8")
        ATYP = ATYP.to_bytes(1, "big")
        DST_PORT = address[1].to_bytes(2, "big")
        return RSV + FRAG + ATYP + DST_ADDR + DST_PORT + data

    def datagram_received(self, data: bytes, address: AddressType) -> None:
        if self.local_is_zero() or address == self.local_address:
            # parse socks5
            try:
                message, target = self.parse_socks5_header(data)
            except (AssertionError, IndexError):
                return

            if self.local_is_zero():
                self.local_address = address

            msg, addr = self.from_local(message, target)
            self.transport.sendto(msg, addr)
            logger.debug(f"{addr} >U< {msg}")
        else:
            msg = self.add_socks5_header(*self.from_remote(data, address))
            self.transport.sendto(msg, self.local_address)
            logger.debug(f"{self.local_address} >U< {msg}")


class UDPSession(BaseSession):
    """
    UDP ASSOCIATE Session
    """

    def from_local(
        self, message: bytes, address: AddressType
    ) -> Tuple[bytes, AddressType]:
        return message, address

    def from_remote(
        self, message: bytes, address: AddressType
    ) -> Tuple[bytes, AddressType]:
        return message, address

    async def create_udp_server(
        self, *, max_time: int = 3
    ) -> Tuple[asyncio.DatagramTransport, Any]:
        host = self.sock.address[0]

        for _ in range(max_time):
            try:
                port = randint(1025, 65535)
                return await asyncio.get_event_loop().create_datagram_endpoint(
                    lambda: UDPProtocol(
                        (self.host, self.port), self.from_local, self.from_remote,
                    ),
                    (host, port),
                )
            except OSError:  # can't bind address
                pass
        raise OSError("Can't bind a port to create udp server.")

    async def run(self) -> None:
        try:
            transport, protocol = await self.create_udp_server(max_time=3)
            await self.sock.send(create_replication(Status.SUCCEEDED))
        except OSError:
            await self.sock.send(
                create_replication(Status.GENERAL_SOCKS_SERVER_FAILURE)
            )
            return

        try:
            while not self.sock.closed:
                await asyncio.sleep(5)
                await self.sock.send(b"heartbeat")
        except ConnectionResetError:
            pass  # RFC1928: tcp close, should close udp server
        finally:
            transport.close()
