import logging
import selectors
import socket
import sys
import threading
import time
import traceback
import random

logger = logging.getLogger("Socks5")


class Socks5Error(Exception):
    pass


class AuthenticationError(Socks5Error):
    pass


# Empty byte
EMPTY = b''
# Response Type
SUCCEEDED = 0
GENERAL_SOCKS_SERVER_FAILURE = 1
CONNECTION_NOT_ALLOWED_BY_RULESET = 2
NETWORK_UNREACHABLE = 3
HOST_UNREACHABLE = 4
CONNECTION_REFUSED = 5
TTL_EXPIRED = 6
COMMAND_NOT_SUPPORTED = 7
ADDRESS_TYPE_NOT_SUPPORTED = 8


def judge(ip: str) -> int:
    try:
        socket.inet_aton(ip)
        return 4
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return 6
    except OSError:
        return 0


class BaseSessoin:
    """
    Client session
    Subclass must set handler
    """

    def __init__(self, sock: socket.socket, address: tuple):
        self.socket = sock
        self.address = address
        self.auth = BaseAuthentication(self)

    def recv(self, num: int) -> bytes:
        data = self.socket.recv(num)
        logger.debug("<<< %s" % data)
        if data == EMPTY:
            raise ConnectionError("Recv a empty bytes that may FIN or RST")
        return data

    def send(self, data: bytes) -> int:
        self.socket.sendall(data)
        logger.debug(">>> %s" % data)
        return len(data)

    def start(self):
        try:
            self.negotiate()
        except Socks5Error as e:
            logger.error(e)
            self.socket.close()
        except (ConnectionError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError) as e:
            logger.error(e)

    def negotiate(self):
        data = self.recv(2)
        VER, NMETHODS = data
        if VER != 5:
            self.send(b"\x05\xff")
            raise Socks5Error("Unsupported version!")
        METHODS = set(self.recv(NMETHODS))
        METHOD = self.auth.getMethod(METHODS)
        reply = b'\x05' + METHOD.to_bytes(1, 'big')
        self.send(reply)
        if METHOD == 255:
            raise Socks5Error("No methods available")
        self.auth.authenticate()
        del self.auth
        data = self.recv(4)
        VER, CMD, RSV, ATYP = data
        if VER != 5:
            self.reply(GENERAL_SOCKS_SERVER_FAILURE)
            raise Socks5Error("Unsupported version!")
        # Parse target address
        if ATYP == 1:  # IPV4
            ipv4 = self.recv(4)
            DST_ADDR = socket.inet_ntoa(ipv4)
        elif ATYP == 3:  # Domain
            addr_len = int.from_bytes(self.recv(1), byteorder='big')
            DST_ADDR = self.recv(addr_len).decode()
        elif ATYP == 4:  # IPV6
            ipv6 = self.recv(16)
            DST_ADDR = socket.inet_ntop(socket.AF_INET6, ipv6)
        else:
            self.reply(ADDRESS_TYPE_NOT_SUPPORTED)
            raise Socks5Error("Unsupported ATYP value: %s" % ATYP)
        DST_PORT = int.from_bytes(self.recv(2), 'big')
        logger.info("Client reuqest %s:%s" % (DST_ADDR, DST_PORT))
        if CMD == 1:
            self.socks5_connect(ATYP, DST_ADDR, DST_PORT)
        elif CMD == 2:
            self.socks5_bind(ATYP, DST_ADDR, DST_PORT)
        elif CMD == 3:
            self.socks5_udp_associate(ATYP, DST_ADDR, DST_PORT)
        else:
            self.reply(COMMAND_NOT_SUPPORTED)
            raise Socks5Error("Unsupported CMD value: %s" % CMD)

    def reply(self, REP: int, ATYP: int = 1, IP: str = "127.0.0.1", port: int = 1080):
        VER, RSV = b'\x05', b'\x00'
        if ATYP == 1:
            BND_ADDR = socket.inet_aton(IP)
        elif ATYP == 4:
            BND_ADDR = socket.inet_pton(socket.AF_INET6, IP)
        elif ATYP == 3:
            BND_ADDR = len(IP).to_bytes(2, 'big') + IP.encode("UTF-8")
        else:
            raise Socks5Error("Unsupported ATYP value: %s" % ATYP)
        REP = REP.to_bytes(1, 'big')
        ATYP = ATYP.to_bytes(1, 'big')
        BND_PORT = int(port).to_bytes(2, 'big')
        reply = VER + REP + RSV + ATYP + BND_ADDR + BND_PORT
        self.send(reply)

    def socks5_connect(self, ATYP: int, address: str, port: int):
        """ must be overwrited """
        self.reply(GENERAL_SOCKS_SERVER_FAILURE)
        self.socket.close()

    def socks5_bind(self, ATYP: int, address: str, port: int):
        """ must be overwrited """
        self.reply(GENERAL_SOCKS_SERVER_FAILURE)
        self.socket.close()

    def socks5_udp_associate(self, ATYP: int, address: str, port: int):
        """ must be overwrited """
        self.reply(GENERAL_SOCKS_SERVER_FAILURE)
        self.socket.close()


class BaseAuthentication:

    def __init__(self, session):
        self.session = session

    def getMethod(self, methods: set) -> int:
        """
        Return a allowed authentication method or 255
        Must be overwrited.
        """
        return 255

    def authenticate(self):
        """
        Authenticate user
        Must be overwrited.
        """
        raise AuthenticationError()


class NoAuthentication(BaseAuthentication):
    """ NO AUTHENTICATION REQUIRED """

    def getMethod(self, methods: set) -> int:
        if 0 in methods:
            return 0
        return 255

    def authenticate(self):
        pass


class PasswordAuthentication(BaseAuthentication):
    """ USERNAME/PASSWORD """

    def _getUser(self) -> dict:
        return {"AberSheeran": "password123"}

    def getMethod(self, methods: set) -> int:
        if 2 in methods:
            return 2
        return 255

    def authenticate(self):
        VER = self.session.recv(1)
        if VER != 5:
            self.session.send(b"\x05\x01")
            raise Socks5Error("Unsupported version!")
        ULEN = int.from_bytes(self.session.recv(1), 'big')
        UNAME = self.session.recv(ULEN).decode("ASCII")
        PLEN = int.from_bytes(self.session.recv(1), 'big')
        PASSWD = self.session.recv(PLEN).decode("ASCII")
        if self._getUser().get(UNAME) and self._getUser().get(UNAME) == PASSWD:
            self.session.send(b"\x05\x00")
        else:
            self.session.send(b"\x05\x01")
            raise AuthenticationError("USERNAME or PASSWORD ERROR")


class DefaultSession(BaseSessoin):
    """ NO AUTHENTICATION REQUIRED Session"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth = NoAuthentication(self)
        # TCP Connect
        self.sel = None
        # UDP
        self.alive = None

    def _forward(self, sender: socket.socket, receiver: socket.socket):
        data = sender.recv(4096)
        if data == EMPTY:
            self._disconnect(sender, receiver)
            raise ConnectionAbortedError("The client or destination has interrupted the connection.")
        receiver.sendall(data)
        logger.debug(f">=< {data}")

    def _connect(self, local: socket.socket, remote: socket.socket):
        self.sel.register(local, selectors.EVENT_READ, self._forward)
        self.sel.register(remote, selectors.EVENT_READ, self._forward)
        while True:
            events = self.sel.select(timeout=5)
            for key, mask in events:
                callback = key.data
                if key.fileobj == local:
                    callback(key.fileobj, remote)
                elif key.fileobj == remote:
                    callback(key.fileobj, local)

    def _disconnect(self, local: socket.socket, remote: socket.socket):
        self.sel.unregister(local)
        self.sel.unregister(remote)
        local.close()
        remote.close()

    def socks5_connect(self, ATYP: int, address: str, port: int):
        try:
            remote = socket.create_connection((address, port), timeout=5)
            self.reply(SUCCEEDED)
        except socket.timeout:
            self.reply(CONNECTION_REFUSED)
            logger.warning("Connection refused from %s:%s" % (address, port))
            return
        try:
            self.sel = selectors.DefaultSelector()
            self._connect(self.socket, remote)
        except (ConnectionError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError):
            return

    def _heartbeat(self):
        try:
            self.alive = True
            while True:
                self.send(b"heartbeat")
                time.sleep(5)
        except (ConnectionError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError):
            self.alive = False

    def parse_udp_header(self, data: bytes) -> ((str, int), bytes):
        _data = bytearray(data)

        def recv(num: int) -> bytes:
            if num == -1:
                return bytes(_data)
            r = _data[:num]
            del _data[:num]
            return bytes(r)
        RSV = recv(2)
        FRAG = recv(1)
        if int.from_bytes(FRAG, 'big') != 0:
            return None
        ATYP = int.from_bytes(recv(1), 'big')
        # Parse target address
        if ATYP == 1:  # IPV4
            ipv4 = recv(4)
            DST_ADDR = socket.inet_ntoa(ipv4)
        elif ATYP == 3:  # Domain
            addr_len = int.from_bytes(recv(1), 'big')
            DST_ADDR = recv(addr_len).decode()
        elif ATYP == 4:  # IPV6
            ipv6 = recv(16)
            DST_ADDR = socket.inet_ntop(socket.AF_INET6, ipv6)
        else:
            return None
        DST_PORT = int.from_bytes(recv(2), 'big')
        return ((DST_ADDR, DST_PORT), recv(-1))

    def add_udp_header(self, data: bytes, address: (str, int)) -> bytes:
        RSV, FRAG = b'\x00\x00', b'\x00'
        t = judge(address[0])
        if t == 4:
            ATYP = 1
            DST_ADDR = socket.inet_aton(address[0])
        elif t == 6:
            ATYP = 4
            DST_ADDR = socket.inet_pton(socket.AF_INET6, address[0])
        else:
            DST_ADDR = int(address[0]).to_bytes(2, 'big') + address[0].encode("UTF-8")
            ATYP = 3
        ATYP = ATYP.to_bytes(1, 'big')
        DST_PORT = address[1].to_bytes(2, 'big')
        reply = RSV + FRAG + ATYP + DST_ADDR + DST_PORT + data
        return reply

    def socks5_udp_associate(self, ATYP: int, address: str, port: int):
        udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for _ in range(3):
            try:
                udp_port = random.randint(1024, 65535)
                udp_server.bind(("0.0.0.0", udp_port))
                break
            except OSError:
                continue
        else:
            self.reply(GENERAL_SOCKS_SERVER_FAILURE)
        self.reply(SUCCEEDED, IP=self.socket.getsockname()[0], port=udp_port)
        threading.Thread(target=self._heartbeat, daemon=True).start()
        while self.alive:
            try:
                msg, addr = udp_server.recvfrom(8192)
                logger.debug(">>> %s" % msg)
                if address == "0.0.0.0":
                    address = addr
                if address == addr:
                    try:
                        target, data = self.parse_udp_header(msg)
                    except TypeError:
                        continue
                    udp_server.sendto(data, target)
                else:
                    udp_server.sendto(self.add_udp_header(msg, addr), address)
            except (ConnectionError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError):
                continue


class Socks5:
    """
    A socks5 server
    """

    def __init__(self, ip: str = "0.0.0.0", port: int = 1080, session: BaseSessoin = DefaultSession):
        self.session = session
        self.server = socket.socket(socket.AF_INET)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((ip, port))
        self.server.listen(13)
        logger.info("Socks5 Server running on %s:%s" % (ip, port))

    def __del__(self):
        self.server.close()
        logger.info("Socks5 Server closed")

    def _link(self, sock: socket.socket, address: (str, int)):
        logger.info("Connection from %s:%s" % address)
        session = self.session(sock, address)
        session.start()
        del session

    def master_worker(self):
        while True:
            try:
                sock, address = self.server.accept()
                client = threading.Thread(
                    target=self._link,
                    args=(sock, address),
                    daemon=True
                )
                client.start()
            except socket.error:
                logger.error("A error in connection from %s:%s" % address)
                traceback.print_exc()

    def run(self):
        worker = threading.Thread(target=self.master_worker, daemon=True)
        worker.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    logger.setLevel(logging.DEBUG)
    Socks5().run()
