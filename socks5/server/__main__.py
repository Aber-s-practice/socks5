import sys
import logging

from .core import Socks5, logger


logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger.setLevel(logging.INFO)

try:
    Socks5(host=sys.argv[1], port=int(sys.argv[2])).run()
except IndexError:
    Socks5().run()
