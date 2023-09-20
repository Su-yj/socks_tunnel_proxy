import asyncio
from asyncio import StreamReader, StreamWriter
from typing import Union, Callable

import settings
from logger import logger


class SocketConnection(object):
    """原始套接字方式连接"""

    async def server_start(self, server, host: str, port: int, client_connected_cb: Callable, *args, **kwargs):
        """
        开启 tunnel 服务
        :param server: 当前服务端的对象
        :param host: 绑定的地址
        :param port: 绑定的端口
        :param client_connected_cb: 客户端连接建立后的回调
        :param args:
        :param kwargs:
        :return:
        """
        return await asyncio.start_server(client_connected_cb, host, port)

    async def server_recv(self, server, reader: StreamReader, writer: StreamWriter, bufsize: int, exactly: bool = True,
                          *args, **kwargs):
        """
        服务端接收数据的方式
        :param server: 当前服务端的对象
        :param reader: StreamReader
        :param writer: StreamWriter
        :param bufsize: 读取数据的大小
        :param exactly: 精确的获取指定的数据大小
        :param args:
        :param kwargs:
        :return:
        """
        if exactly:
            data = await reader.readexactly(bufsize)
        else:
            data = await reader.read(bufsize)
        # logger.debug(f'server recv data: {data}')
        return data

    async def server_send(self, server, reader: StreamReader, writer: StreamWriter, data: Union[bytes, bytearray],
                          *args, **kwargs):
        """
        服务端发送数据的方式
        :param server: 当前服务端的对象
        :param reader: StreamReader
        :param writer: StreamWriter
        :param data: 待发送的数据
        :param args:
        :param kwargs:
        :return:
        """
        # logger.debug(f'server send data: {data}')
        writer.write(data)
        await writer.drain()

    async def agent_start(self, server, host: str, port: int, *args, **kwargs) -> tuple[StreamReader, StreamWriter]:
        """
        agent 端开启与服务端的连接
        :param server: 当前 Agent 端的对象
        :param host: 地址
        :param port: 端口
        :param args:
        :param kwargs:
        :return:
        """
        try:
            return await asyncio.open_connection(host=host, port=port)
        except ConnectionRefusedError:
            if (settings.TUNNEL_SERVER_RETRY > 0 and server.retry < settings.TUNNEL_SERVER_RETRY) or \
                    settings.TUNNEL_SERVER_RETRY <= 0:
                await asyncio.sleep(settings.TUNNEL_SERVER_CONNECT_INTERVAL)
                server.retry += 1
                logger.warning(f'reconnect to server: {server.retry} times')
                return await self.agent_start(server, host, port, *args, **kwargs)
            raise

    async def agent_recv(self, server, reader: StreamReader, writer: StreamWriter, bufsize: int, exactly: bool = True,
                         *args, **kwargs):
        """
        服务端接收数据的方式
        :param server: 当前 agent 端的对象
        :param reader: StreamReader
        :param writer: StreamWriter
        :param bufsize: 读取数据的大小
        :param exactly: 精确的获取数据大小
        :param args:
        :param kwargs:
        :return:
        """
        if exactly:
            data = await reader.readexactly(bufsize)
        else:
            data = await reader.read(bufsize)
        # logger.debug(f'agent recv data: {data}')
        return data

    async def agent_send(self, server, reader: StreamReader, writer: StreamWriter, data: Union[bytes, bytearray],
                         *args, **kwargs):
        """
        服务端发送数据的方式
        :param server: 当前 agent 端的对象
        :param reader: StreamReader
        :param writer: StreamWriter
        :param data: 待发送的数据
        :param args:
        :param kwargs:
        :return:
        """
        # logger.debug(f'agent send data: {data}')
        writer.write(data)
        await writer.drain()
