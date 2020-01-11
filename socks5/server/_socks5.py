from socket import inet_pton, AF_INET, AF_INET6

from socks5.values import Status, Atyp
from socks5.utils import judge_atyp


def create_replication(
    status: Status, host: str = "127.0.0.1", port: int = 1080
) -> bytes:
    """
    Constructing a response for socks5.
    """
    VER, RSV = b"\x05", b"\x00"
    ATYP = judge_atyp(host)
    if ATYP == Atyp.IPV4:
        BND_ADDR = inet_pton(AF_INET, host)
    elif ATYP == Atyp.IPV6:
        BND_ADDR = inet_pton(AF_INET6, host)
    elif ATYP == Atyp.DOMAIN:
        BND_ADDR = len(host).to_bytes(2, "big") + host.encode("UTF-8")
    REP = status.to_bytes(1, "big")
    ATYP = ATYP.to_bytes(1, "big")
    BND_PORT = int(port).to_bytes(2, "big")
    return VER + REP + RSV + ATYP + BND_ADDR + BND_PORT
