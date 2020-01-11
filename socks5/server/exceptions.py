class Socks5Error(Exception):
    pass


class NoVersionAllowed(Socks5Error):
    pass


class NoCommandAllowed(Socks5Error):
    pass


class NoATYPAllowed(Socks5Error):
    pass


class AuthenticationError(Socks5Error):
    pass


class NoAuthenticationAllowed(AuthenticationError):
    pass
