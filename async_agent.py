import asyncio
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ModuleNotFoundError:
    pass
import struct
import time
from asyncio import StreamReader, StreamWriter, IncompleteReadError
from typing import Optional

import exceptions
import settings
from async_base import BaseServer
from logger import logger


class Agent(BaseServer):
    _TYPE = 'agent'

    def __init__(self):
        # 当前 agent 连接服务器后的 stream：(StreamReader, StreamWriter)
        self.reader: Optional[StreamReader] = None
        self.writer: Optional[StreamWriter] = None
        # 重试次数
        self.retry = 0
        # 映射表
        self.client_remote_map: dict[bytes, tuple[StreamReader, StreamWriter]] = {}
        # 最后一次收到服务器 ping 的时间
        self.ping_time = None

    # #################### 下面是 agent 客户端的逻辑处理 ####################
    @logger.catch
    async def start_server(self):
        """开启服务"""
        # 先检查一下是否需要关闭之前的连接
        await self.init()
        self.reader, self.writer = await self.call(
            backend_path=settings.CONNECTION_BACKEND,
            method='agent_start',
            host=settings.TUNNEL_SERVER_HOST,
            port=settings.TUNNEL_SERVER_PORT,
        )
        if not await self.call(
                backend_path=settings.AUTHENTICATION_BACKEND,
                method='agent',
                reader=self.reader,
                writer=self.writer,
        ):
            raise exceptions.AuthenticationFailedException()
        # 连接成功后，每次都需要重置重试次数
        self.retry = 0
        logger.info(f'tunnel server connected: ({settings.TUNNEL_SERVER_HOST}, {settings.TUNNEL_SERVER_PORT})')
        try:
            await asyncio.gather(
                self.handle_cmd(),
                # self.ping(),
                # self.check_pong(),
            )
        except KeyboardInterrupt:
            raise
        except Exception as e:
            logger.exception(f'agent error: {e}')
            logger.warning('agent will restart')
            await self.start_server()

    async def ping(self):
        """定时发送 ping 数据"""
        data = struct.pack('!B', 0x05)
        while True:
            await self.send(self.reader, self.writer, data)
            await asyncio.sleep(settings.PING_INTERVAL)

    async def check_pong(self):
        """检查服务端的 pong 响应是否正常"""
        while True:
            await asyncio.sleep(settings.PING_INTERVAL)
            # 如果上次 pong 的时间大于配置设置时间间隔的3倍，则认为超时了，对方已死
            if time.time() - self.ping_time > settings.PING_INTERVAL * 3:
                raise exceptions.PingPongTimeOutException

    async def handle_cmd(self):
        """处理服务器发过来的指令"""
        while True:
            try:
                data = await self.recv(self.reader, self.writer, 1)
            except (ConnectionResetError, IncompleteReadError):
                logger.warning('tunnel server disconnected')
                raise
            _type = struct.unpack('!B', data)[0]
            # logger.debug(f'type: {_type}')
            # 创建新的 socket 连接
            if _type == 0x01:
                id_bytes = await self.get_id_bytes(self.reader, self.writer)
                cmd = struct.unpack('!B', await self.recv(self.reader, self.writer, 1))
                atyp, dst_addr, dst_port = await self.parse_socks5_addr_port(self.reader, self.writer)
                asyncio.ensure_future(self.create_connect(id_bytes, dst_addr, dst_port))
            # socks5 数据交换处理阶段
            elif _type == 0x02:
                id_bytes = await self.get_id_bytes(self.reader, self.writer)
                length = struct.unpack('!H', await self.recv(self.reader, self.writer, 2))[0]
                req_data = await self.recv(self.reader, self.writer, length)
                asyncio.ensure_future(self.remote_relay(id_bytes, req_data))
            # 关闭创建的 socket 连接
            elif _type == 0x03:
                id_bytes = await self.get_id_bytes(self.reader, self.writer)
                asyncio.ensure_future(self.close_connect(id_bytes))
            # agent 向服务端发送连接断开的处理（理论上不会进入这里）
            elif _type == 0x04:
                await self.recv(self.reader, self.writer, 1)
            # 服务端向客户端发送 ping 数据
            elif _type == 0x05:
                asyncio.ensure_future(self.handle_ping())
            # 服务端向客户端回复 pong 数据（不需要处理）
            elif _type == 0x06:
                pass
            else:
                raise exceptions.UnknownCMDException()

    async def create_connect(self, id_bytes, dst_addr, dst_port):
        """创建连接"""
        # id_bytes = await self.get_id_bytes(self.reader, self.writer)
        # cmd = struct.unpack('!B', await self.recv(self.reader, self.writer, 1))
        # atyp, dst_addr, dst_port = await self.parse_socks5_addr_port(self.reader, self.writer)
        # 创建套接字连接
        try:
            logger.debug(f'create connect: {dst_addr}:{dst_port}')
            reader, writer = await asyncio.open_connection(host=dst_addr, port=dst_port)
        except Exception as e:
            logger.debug(f'cannot connect the server({dst_addr}, {dst_port}): {e}')
            # 告诉服务端创建连接失败
            data = struct.pack('!BB', 0x01, len(id_bytes)) + id_bytes
            data += struct.pack('!BBIH', 0x05, 0x01, 0x00, 0x00)
            return await self.send(self.reader, self.writer, data)
        # 保存映射关系
        # logger.debug(f'save map: id_bytes: {id_bytes}, reader: {reader}, writer: {writer}')
        await self.save_map(id_bytes, reader, writer)
        # 创建连接成功返回
        data = struct.pack('!BB', 0x01, len(id_bytes)) + id_bytes
        data += struct.pack('!BBIH', 0x00, 0x01, 0x00, 0x00)
        await self.send(self.reader, self.writer, data)
        # TODO: 不确定这样做行不行
        # 处理 remote 的数据返回
        await self.handle_remote_recv(id_bytes, reader, writer)
        # asyncio.ensure_future(self.handle_remote_recv(id_bytes, reader, writer))

    async def handle_remote_recv(self, id_bytes: bytes, reader: StreamReader, writer: StreamWriter):
        """
        处理 remote 的数据返回
        :param id_bytes: 代理客户端的 ID 标识
        :param reader: remote 的 StreamReader
        :param writer: remote 的 StreamWriter
        :return:
        """
        while True:
            try:
                resp_data = await reader.read(settings.BUFFER_SIZE)
                # logger.debug(f'recv remote data: {resp_data}')
                if not resp_data:
                    break
                data = struct.pack('!BB', 0x02, len(id_bytes)) + id_bytes
                data += struct.pack('!H', len(resp_data)) + resp_data
                await self.send(self.reader, self.writer, data)
            except Exception as e:
                logger.error(f'remote recv error: {e}')
                break
        # 不管是发生异常还是数据已经接收完毕了，最终还是需要通知服务端数据连接断开
        data = struct.pack('!BB', 0x04, len(id_bytes)) + id_bytes
        await self.send(self.reader, self.writer, data)
        # 并且把映射删除
        await self.remove_map(id_bytes)
        # 关闭连接
        await self.close_writer(writer)

    async def remote_relay(self, id_bytes: bytes, req_data: bytes):
        """处理 relay 阶段的数据"""
        # 获取当前 id 对应的 remote streams
        reader, writer = await self.get_streams(id_bytes)
        # 如果没有 writer，说明当前连接已断开
        if not writer:
            data = struct.pack('!BB', 0x04, len(id_bytes)) + id_bytes
            return await self.send(self.reader, self.writer, data)
        writer.write(req_data)
        await writer.drain()
        # asyncio.ensure_future(writer.drain())

    async def close_connect(self, id_bytes: bytes):
        """关闭 remote 的连接"""
        reader, writer = await self.get_streams(id_bytes)
        await self.close_writer(writer)
        await self.remove_map(id_bytes)

    async def handle_ping(self):
        """处理服务端发送过来的 ping"""
        # 记录一下当前的时间
        self.ping_time = time.time()
        # 回复 pong 给服务端
        await self.send(self.reader, self.writer, struct.pack('!B', 0x06))

    # #################### 下面是通用方法 ####################
    async def init(self):
        """初始化 agent 客户端"""
        await self.close_writer(self.writer)
        self.reader = None
        self.writer = None
        self.retry = 0
        for reader, writer in self.client_remote_map.values():
            await self.close_writer(writer)
        self.client_remote_map = {}
        self.ping_time = None

    async def save_map(self, id_bytes: bytes, reader: StreamReader, writer: StreamWriter):
        """
        保存代理客户端 ID 和目标地址的 streams 对应关系
        :param id_bytes: id 标识的 bytes
        :param reader: 创建连接后的 StreamReader
        :param writer: 创建连接后的 StreamWriter
        :return:
        """
        self.client_remote_map[id_bytes] = (reader, writer)

    async def remove_map(self, id_bytes: bytes):
        """
        删除代理客户端 ID 和目标地址的 streams 的对应关系
        :param id_bytes: 待删除的 id
        :return:
        """
        return self.client_remote_map.pop(id_bytes, None)

    async def get_streams(self, id_bytes: bytes) -> tuple[Optional[StreamReader], Optional[StreamWriter]]:
        """
        根据 id 获取对应 remote 的 streams
        :param id_bytes: id 标识
        :return:
        """
        streams = self.client_remote_map.get(id_bytes)
        if not streams:
            return None, None
        if streams[0].at_eof() or streams[1].is_closing():
            await self.close_writer(streams[1])
            await self.remove_map(id_bytes)
            return None, None
        return streams


if __name__ == '__main__':
    agent = Agent()
    asyncio.run(agent.start_server())
