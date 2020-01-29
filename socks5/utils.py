import asyncio
from typing import Any, Set, Awaitable
from socket import AF_INET, AF_INET6, inet_pton
from asyncio import Future, Task

from .values import Atyp


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
    finished, result, _future = 0, loop.create_future(), None

    def _done_callback(fut: Future) -> None:
        nonlocal finished, result, _future

        if result.cancelled():
            return  # nothing to do on cancelled

        try:
            fut.result()  # try raise exception
        except Exception:
            pass

        finished += 1

        if _future is None:
            _future = fut

        map(lambda task: task.cancel(), filter(lambda task: not task.done(), tasks))

        if finished == len(tasks):
            try:
                result.set_result(_future.result())
            except Exception:
                result.set_exception(_future.exception())

    for coro in coros:
        task = loop.create_task(coro)
        task.add_done_callback(_done_callback)
        tasks.add(task)

    result.add_done_callback(
        lambda fut: map(
            lambda task: task.cancel(), filter(lambda task: not task.done(), tasks)
        )
    )

    return result
