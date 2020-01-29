import typing
import asyncio

# TODO


async def create_connection(*args, **kwargs) -> typing.Any:
    return asyncio.get_event_loop().create_connection(*args, **kwargs)


async def create_datagram_endpoint(*args, **kwargs) -> typing.Any:
    return asyncio.get_event_loop().create_datagram_endpoint(*args, **kwargs)
