import asyncio
import warnings
from asyncio import Task, Future
from socket import AF_INET, AF_INET6, inet_pton
from typing import Set

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


def onlyfirst(*coros, loop=None) -> Future:
    """
    Execute multiple coroutines concurrently, returning only the results of the first execution.

    When one is completed, the execution of other coroutines will be canceled.
    """
    loop = loop or asyncio.get_running_loop()
    tasks: Set[Task] = set()
    result, _future = loop.create_future(), None

    def _done_callback(fut: Future) -> None:
        nonlocal result, _future

        if result.cancelled():
            return  # nothing to do on onlyfirst cancelled

        if _future is None:
            _future = fut  # record first completed future

        cancel_all_task()

        try:
            result.set_result(_future.result())
        except Exception:
            result.set_exception(_future.exception())

    def cancel_all_task() -> None:
        for task in tasks:
            task.remove_done_callback(_done_callback)

        for task in filter(lambda task: not task.done(), tasks):
            task.cancel()

    for coro in coros:
        task: Task = loop.create_task(coro)
        task.add_done_callback(_done_callback)
        tasks.add(task)

    result.add_done_callback(lambda fut: cancel_all_task())

    return result


class TCPSocket(Socket):
    """
    wrapper asyncio.StreamReader, asyncio.StreamWriter
    """

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.r = reader
        self.w = writer
        self.__address = writer.get_extra_info("peername")

    def __del__(self) -> None:
        if not self.closed:
            warnings.warn(
                f"{self.w.get_extra_info('sockname')}=={self.w.get_extra_info('peername')} not closed."
            )

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
