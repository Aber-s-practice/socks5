import os
import sys
import time
import socket
import traceback
import subprocess

try:
    import socks

    socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 1081)
    socket.socket = socks.socksocket
except ImportError:
    sys.exit("You must install `socks` to run test.\nlike run `pip install pysocks`")

sys.path.insert(0, os.getcwd())

process = subprocess.Popen(f"{sys.executable} -m socks5.server 127.0.0.1 1081")

time.sleep(1)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
        ("8.8.8.8", 53),
    )
    sock.settimeout(3)
    sock.recv(4096)
    sock.close()
except socket.error:
    traceback.print_exc()

try:
    sock = socket.create_connection(("abersheeran.com", 80))
    # sock = socket.create_connection(("google.com", 80))
    sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
    sock.recv(4096)
    sock.close()
except socket.error:
    traceback.print_exc()

time.sleep(9)

process.terminate()
process.wait()
