import struct
from asyncio import StreamReader, StreamWriter

from async_base import BaseServer


class AnonymousAuthentication(object):
    """无需认证"""
    async def server(self, server: BaseServer, reader: StreamReader, writer: StreamWriter, *args, **kwargs) -> bool:
        """
        服务端认证 tunnel 客户端数据是否正常
        :param server: 当前的 server 对象
        :param reader: tunnel 的 StreamReader
        :param writer: tunnel 的 StreamWriter
        :param args:
        :param kwargs:
        :return:
        """
        await server.recv(reader, writer, 1024, exactly=False)
        await server.send(reader, writer, struct.pack('!B', 0x00))
        return True

    async def agent(self, server: BaseServer, reader: StreamReader, writer: StreamWriter, *args, **kwargs):
        """
        agent 端发起 tunnel 的认证
        :param server: 当前 agent 客户端的对象
        :param reader: agent 的 StreamReader
        :param writer: agent 的 StreamWriter
        :param args:
        :param kwargs:
        :return:
        """
        await server.send(reader, writer, b'hello')
        result = struct.unpack('!B', await server.recv(reader, writer, 1))[0]
        return result == 0x00
