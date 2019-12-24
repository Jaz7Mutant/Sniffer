def format_mac(address: bytes) -> str:
    bytes_str = map('{:02x}'.format, address)
    return ':'.join(bytes_str).upper()


def ipv6(address: bytes) -> str:
    addr = ''.join(map('{:02X}'.format, address))
    return (f'{addr[0:4]}:{addr[4:8]}:{addr[8:12]}:{addr[12:16]}:{addr[16:20]}'
            f':{addr[20:24]}:{addr[24:28]}:{addr[28:32]}')


def ipv4(address: bytes) -> str:
    return '.'.join(map(str, address))
