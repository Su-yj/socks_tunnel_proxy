import ipaddress
import platform
import socket
import struct
from typing import Union

import exceptions


def get_socket_addr_port(sock: socket.socket) -> tuple[str, int]:
    """
    获取客户端 socket 套接字的地址和端口
    :param sock: 客户端的 socket
    :return: 地址和端口
    """
    # IPV4
    if sock.family == socket.AF_INET:
        addr, port = sock.getpeername()
    # IPV6
    else:
        addr, port, _, _ = sock.getpeername()
    return addr, port


def get_ip_type(ip_address: str) -> int:
    """
    判断某个地址是 ipv4 还是 ipv6
    :param ip_address: IP 地址
    :return: 4 表示 IPV4 地址；6 表示 IPV6 地址
    """
    ip_obj = ipaddress.ip_address(ip_address)
    return ip_obj.version


def parse_socks5_addr_port(sock: socket.socket) -> tuple[int, str, int]:
    """
    处理 socks5 代理协议中请求阶段的 IP 地址和端口
    :param sock: 客户端的 socket 连接对象
    :return: 地址类型, 地址, 端口
    """
    atyp = struct.unpack('!B', sock.recv(1))[0]
    # IPV4
    if atyp == 0x01:
        addr = socket.inet_ntop(socket.AF_INET, sock.recv(4))
    # Domain name
    elif atyp == 0x03:
        domain_length = ord(sock.recv(1))
        addr = sock.recv(domain_length).decode()
    # IPV6
    elif atyp == 0x04:
        addr = socket.inet_ntop(socket.AF_INET6, sock.recv(6))
    else:
        raise exceptions.UnknownTypeException('未知的类型: %s' % atyp)
    port = struct.unpack('!H', sock.recv(2))[0]
    return atyp, addr, port


def transform_addr_port_to_bytes(addr: str, port: Union[int, str]) -> bytes:
    """
    把 地址 和 端口 转换成 socks5 协议中请求阶段的 bytes
    :param addr: 地址
    :param port: 端口
    :return: atype[1] + addr[Variable] + port[2]
    """
    try:
        atyp = 0x01 if get_ip_type(addr) == 4 else 0x04
    except ValueError:
        atyp = 0x03
    # IPV4
    if atyp == 0x01:
        address = socket.inet_pton(socket.AF_INET, addr)
    # Domain name
    elif atyp == 0x03:
        address = addr.encode()
        length = chr(len(address)).encode()
        address = length + address
    # IPV6
    else:
        address = socket.inet_pton(socket.AF_INET6, addr)
    return struct.pack('!B', atyp) + address + struct.pack('!H', int(port))


# https://stackoverflow.com/questions/12248132/how-to-change-tcp-keepalive-timer-using-python-script
def set_keepalive_linux(sock: socket.socket, after_idle_sec: int = 1, interval_sec: int = 3, max_fails: int = 5):
    """Set TCP keepalive on an open socket.

    It activates after 1 second (after_idle_sec) of idleness,
    then sends a keepalive ping once every 3 seconds (interval_sec),
    and closes the connection after 5 failed ping (max_fails), or 15 seconds
    """
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)


def set_keepalive_osx(sock: socket.socket, after_idle_sec: int = 1, interval_sec: int = 3, max_fails: int = 5):
    """Set TCP keepalive on an open socket.

    sends a keepalive ping once every 3 seconds (interval_sec)
    """
    # scraped from /usr/include, not exported by python's socket module
    TCP_KEEPALIVE = 0x10
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, interval_sec)


def set_keepalive_windows(sock: socket.socket, after_idle_sec: int = 1, interval_sec: int = 3, max_fails: int = 5):
    """Set TCP keepalive on an open socket.

    sends a keepalive ping once every 3 seconds (interval_sec),
    and closes the connection after 15 seconds (interval_sec * max_fails)
    """
    sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, interval_sec * max_fails * 1000, interval_sec * 1000))


def set_keepalive(sock: socket.socket, after_idle_sec: int = 1, interval_sec: int = 3, max_fails: int = 5):
    """Set TCP keepalive on an open socket"""
    system = platform.system()

    if system == 'Windows':
        return set_keepalive_windows(sock, after_idle_sec, interval_sec, max_fails)
    elif system == 'Linux':
        return set_keepalive_linux(sock, after_idle_sec, interval_sec, max_fails)
    elif system == 'Darwin':
        return set_keepalive_osx(sock, after_idle_sec, interval_sec, max_fails)
    else:
        raise exceptions.UnknownSystemException('unknown system: %s' % system)


def int2bytes(value: int) -> bytes:
    """
    把10进制的内存地址的值转成16进制后，再转成 bytes
    :param value:
    :return:
    """
    hex_value = hex(value)[2:]
    hex_value = '0' + hex_value if len(hex_value) % 2 else hex_value
    return bytes.fromhex(hex_value)


def bytes2int(value: bytes) -> int:
    """
    把 bytes 的值转换成16进制的整数，再转换成10进制的整形
    :param value: 16进制整数的 bytes
    :return:
    """
    return int(value.hex(), 16)
