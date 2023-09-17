import socket
import struct
from typing import Union

import exceptions
import settings
from utils.module_loading import load_backend


class BaseServer(object):
    # 服务类型，填 server 或 agent
    _TYPE = ''

    def call(self, backend_path: str, method: str, *args, **kwargs):
        """
        执行钩子的方法
        :param backend_path: 钩子的路径
        :param method: 钩子对象的方法
        :param args:
        :param kwargs:
        :return:
        """
        backend = load_backend(backend_path)
        func = getattr(backend, method)
        return func(self, *args, **kwargs)

    def send(self, sock: socket.socket, data: Union[bytes, bytearray]):
        """
        发送数据到 tunnel 客户端
        :param sock: tunnel 套接字
        :param data: 待发送的数据
        :return:
        """
        return self.call(
            backend_path=settings.CONNECTION_BACKEND,
            method=f'{self._TYPE}_send',
            sock=sock,
            data=data,
        )

    def recv(self, sock: socket.socket, bufsize: int):
        """
        接收某个套接字的数据
        :param sock: 需要接收内容的套接字
        :param bufsize: 接收的长度
        :return:
        """
        return self.call(
            backend_path=settings.CONNECTION_BACKEND,
            method=f'{self._TYPE}_recv',
            sock=sock,
            bufsize=bufsize,
        )

    def parse_socks5_addr_port(self, sock: socket.socket) -> tuple[int, str, int]:
        """
        处理 socks5 代理协议中请求阶段的 IP 地址和端口
        :param sock: 客户端的 socket 连接对象
        :return: 地址类型, 地址, 端口
        """
        atyp = struct.unpack('!B', self.recv(sock, 1))[0]
        # IPV4
        if atyp == 0x01:
            addr = socket.inet_ntop(socket.AF_INET, self.recv(sock, 4))
        # Domain name
        elif atyp == 0x03:
            domain_length = ord(self.recv(sock, 1))
            addr = self.recv(sock, domain_length).decode()
        # IPV6
        elif atyp == 0x04:
            addr = socket.inet_ntop(socket.AF_INET6, self.recv(sock, 6))
        else:
            raise exceptions.UnknownTypeException('未知的类型: %s' % atyp)
        port = struct.unpack('!H', self.recv(sock, 2))[0]
        return atyp, addr, port

    @staticmethod
    def int2bytes(value: int) -> bytes:
        """
        把10进制的内存地址的值转成16进制后，再转成 bytes
        :param value:
        :return:
        """
        hex_value = hex(value)[2:]
        hex_value = '0' + hex_value if len(hex_value) % 2 else hex_value
        return bytes.fromhex(hex_value)

    @staticmethod
    def bytes2int(value: bytes) -> int:
        """
        把 bytes 的值转换成16进制的整数，再转换成10进制的整形
        :param value: 16进制整数的 bytes
        :return:
        """
        return int(value.hex(), 16)

    def get_memory_bytes(self, sock: socket.socket) -> bytes:
        """从套接字中获取对应套接字内存的长度，并获取对应套接字的内存地址"""
        length = struct.unpack('!B', self.recv(sock, 1))[0]
        return self.recv(sock, length)

    def sock2bytes(self, sock: socket.socket) -> bytes:
        """
        传入一个套接字，根据内存地址转换成 16 进制后的 bytes
        :param sock: 待转换的套接字
        :return:
        """
        return self.int2bytes(id(sock))

    def sock2send_data(self, sock: socket.socket) -> bytes:
        """
        传入一个套接字，转换成传输协议中的标识 ID
        :param sock: 待转换的套接字
        :return:
        """
        memory_bytes = self.sock2bytes(sock)
        return struct.pack('!B', len(memory_bytes)) + memory_bytes
