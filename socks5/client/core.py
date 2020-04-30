import typing
import asyncio

ADDRESS: typing.Tuple[str, int] = None
USERPASS: typing.Tuple[str, str] = None


def patch(host: str, port: int, username: str = None, password: str = None) -> None:
    assert username is None ^ password is None, "username & password must use together"
    global ADDRESS, USERPASS
    ADDRESS = (host, port)
    if username:
        USERPASS = (username, password)

    setattr(asyncio.get_event_loop(), "create_connection", create_connection)
    setattr(
        asyncio.get_event_loop(), "create_datagram_endpoint", create_datagram_endpoint
    )


# TODO


async def create_connection(*args, **kwargs) -> typing.Any:
    return asyncio.get_event_loop().create_connection(*args, **kwargs)


async def create_datagram_endpoint(*args, **kwargs) -> typing.Any:
    return asyncio.get_event_loop().create_datagram_endpoint(*args, **kwargs)
