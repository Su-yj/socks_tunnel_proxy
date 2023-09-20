import asyncio
import socket
import struct
from asyncio import StreamReader, StreamWriter
from typing import Union

import exceptions
import settings
from utils.module_loading import load_backend


class BaseServer(object):
    # 服务类型，填 server 或 agent
    _TYPE = ''

    async def call(self, backend_path: str, method: str, *args, **kwargs):
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
        return await func(self, *args, **kwargs)

    async def send(self, reader: StreamReader, writer: StreamWriter, data: Union[bytes, bytearray]):
        """
        tunnel 客户端和服务端之间发送数据的方法
        :param reader: StreamReader
        :param writer: StreamWriter
        :param data: 待发送的数据
        :return:
        """
        asyncio.ensure_future(
            self.call(
                backend_path=settings.CONNECTION_BACKEND,
                method=f'{self._TYPE}_send',
                reader=reader,
                writer=writer,
                data=data,
            )
        )
        # return await self.call(
        #     backend_path=settings.CONNECTION_BACKEND,
        #     method=f'{self._TYPE}_send',
        #     reader=reader,
        #     writer=writer,
        #     data=data,
        # )

    async def recv(self, reader: StreamReader, writer: StreamWriter, bufsize: int, exactly: bool = True):
        """
        接收某个套接字的数据
        :param reader: StreamReader
        :param writer: StreamWriter
        :param bufsize: 接收的长度
        :param exactly: 是否需要精确获取数据
        :return:
        """
        return await self.call(
            backend_path=settings.CONNECTION_BACKEND,
            method=f'{self._TYPE}_recv',
            reader=reader,
            writer=writer,
            bufsize=bufsize,
            exactly=exactly,
        )

    async def parse_socks5_addr_port(self, reader: StreamReader, writer: StreamWriter) -> tuple[int, str, int]:
        """
        处理 socks5 代理协议中请求阶段的 IP 地址和端口
        :param reader: StreamReader
        :param writer: StreamWriter
        :return: 地址类型, 地址, 端口
        """
        atyp = struct.unpack('!B', await self.recv(reader, writer, 1))[0]
        # IPV4
        if atyp == 0x01:
            addr = socket.inet_ntop(socket.AF_INET, await self.recv(reader, writer, 4))
        # Domain name
        elif atyp == 0x03:
            domain_length = ord(await self.recv(reader, writer, 1))
            addr = (await self.recv(reader, writer, domain_length)).decode()
        # IPV6
        elif atyp == 0x04:
            addr = socket.inet_ntop(socket.AF_INET6, await self.recv(reader, writer, 6))
        else:
            raise exceptions.UnknownTypeException('未知的类型: %s' % atyp)
        port = struct.unpack('!H', await self.recv(reader, writer, 2))[0]
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

    async def get_id_bytes(self, reader: StreamReader, writer: StreamWriter) -> bytes:
        """
        获取当前请求对应到代理客户端的 ID 标识符
        :param reader: agent 的 StreamReader
        :param writer: agent 的 StreamWriter
        :return:
        """
        length = struct.unpack('!B', await self.recv(reader, writer, 1))[0]
        return await self.recv(reader, writer, length)

    async def mk_id_bytes(self, reader: StreamReader, writer: StreamWriter) -> bytes:
        """
        生成代理客户端的 ID 标识符
        :param reader: 客户端的 StreamReader
        :param writer: 客户端的 StreamWriter
        :return:
        """
        return self.int2bytes(id(reader))

    async def close_writer(self, writer: StreamWriter):
        """
        关闭 StreamWriter
        :param writer: 待关闭的 StreamWriter
        :return:
        """
        if not writer or writer.is_closing():
            return
        writer.close()
        await writer.wait_closed()
