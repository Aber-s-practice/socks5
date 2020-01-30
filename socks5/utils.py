import asyncio
from socket import AF_INET, AF_INET6, inet_pton

from .values import Atyp
from .types import Socket, AddressType


def judge_atyp(host: str) -> int:
    """
    return the host's ATYP.
    """
    try:
        inet_pton(AF_INET, host)
        return Atyp.IPV4
    except OSError:
        pass

    try:
        inet_pton(AF_INET6, host)
        return Atyp.IPV6
    except OSError:
        pass

    return Atyp.DOMAIN


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
        if self.w.is_closing():
            return
        self.w.close()
        await self.w.wait_closed()
