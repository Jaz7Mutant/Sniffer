def format_mac(address: bytes) -> str:
    bytes_str = map('{:02x}'.format, address)
    return ':'.join(bytes_str).upper()


def ipv6(address: bytes) -> str:
    bytes_str = map('{:02x}'.format, address)
    return ':'.join(bytes_str).upper()


def ipv4(address: bytes) -> str:
    return '.'.join(map(str, address))
