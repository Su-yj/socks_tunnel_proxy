import asyncio
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ModuleNotFoundError:
    pass
import random
import socket
import struct
import time
from asyncio import StreamReader, StreamWriter, IncompleteReadError
from typing import Optional

import exceptions
import settings
import utils
from async_base import BaseServer
from logger import logger


class Server(BaseServer):
    _TYPE = 'server'
    # socks proxy version
    SOCKS_VERSION = 0x05

    def __init__(self):
        # socks5 服务
        self.socks5_server = None
        # tunnel 服务
        self.tunnel_server = None
        # socks5 客户端连接的字典，{reader 的 ID bytes: (reader, writer)}
        self.client_map: dict[bytes, tuple[StreamReader, StreamWriter]] = {}
        # tunnel 连接的字典，{reader 的 ID: (reader, writer)}
        self.tunnel_map: dict[int, tuple[StreamReader, StreamWriter]] = {}
        # 记录 tunnel 最后 ping 的时间
        self.tunnel_ping_time: dict[int, float] = {}

    @logger.catch
    async def start_server(self):
        """开启服务"""
        await asyncio.gather(
            self.start_socks5_server(),
            self.start_tunnel_server(),
        )

    # #################### 下面和 socks5 服务相关 ####################
    async def start_socks5_server(self):
        """开启 socks5 服务"""
        self.socks5_server = await asyncio.start_server(
            client_connected_cb=self.handle_socks5_connect,
            host=settings.SOCKS5_BIND_HOST,
            port=settings.SOCKS5_BIND_PORT,
        )
        async with self.socks5_server:
            logger.info(f'start socks5 server: {settings.SOCKS5_BIND_HOST}:{settings.SOCKS5_BIND_PORT}')
            await self.socks5_server.serve_forever()

    async def handle_socks5_connect(self, reader: StreamReader, writer: StreamWriter):
        """
        处理 socks5 客户端的连接
        :param reader: StreamReader
        :param writer: StreamWriter
        :return:
        """
        logger.info(f'client connected: {writer.get_extra_info("peername")}')
        try:
            # 协商版本及认证阶段
            await self.handle_socks5_authenticate(reader, writer)
            # 如果 writer 关闭了，说明认证不通过，不再继续往下执行
            if writer.is_closing():
                return
            # 请求阶段
            tunnel_streams = await self.handle_socks5_request(reader, writer)
            if not tunnel_streams:
                return
            # repay 阶段
            await self.handle_socks5_relay(reader, writer, tunnel_streams[0], tunnel_streams[1])
        except KeyboardInterrupt:
            return
        except Exception as e:
            logger.exception(f'socks5 client handle error: {e}')
            await self.remove_client(reader, writer)
            await self.close_writer(writer)

    async def handle_socks5_authenticate(self, reader: StreamReader, writer: StreamWriter):
        """
        处理 socks5 认证
        :param reader: StreamReader
        :param writer: StreamWriter
        :return:
        """
        try:
            header = await reader.readexactly(2)
        except IncompleteReadError:
            return await self.close_writer(writer)
        version, nmethods = struct.unpack('!BB', header)
        # 版本不正确 或 nmethods 小于等于 0
        if version != self.SOCKS_VERSION or nmethods <= 0x00:
            writer.write(struct.pack('!BB', self.SOCKS_VERSION, 0xFF))
            await writer.drain()
            return await self.close_writer(writer)
        # 把客户端支持的认证方法取出来
        methods = []
        for _ in range(nmethods):
            methods.append(ord(await reader.readexactly(1)))
        # 如果允许匿名，直接告诉客户端即可
        if settings.SOCKS5_ALLOW_ANONYMOUS:
            writer.write(struct.pack('!BB', self.SOCKS_VERSION, 0x00))
            return await writer.drain()
        # 暂时只支持账号密码的认证方式，如果账号密码认证的方法不在里面，则关闭连接
        if 0x02 not in methods:
            writer.write(struct.pack('!BB', self.SOCKS_VERSION, 0xFF))
            await writer.drain()
            return await self.close_writer(writer)
        writer.write(struct.pack('!BB', self.SOCKS_VERSION, 0x02))
        await writer.drain()
        # 身份认证
        try:
            version = await reader.readexactly(1)
        except IncompleteReadError:
            return await self.close_writer(writer)
        # 版本不正确
        if version != b'\x01':
            return await self.close_writer(writer)
        # 账号密码认证
        ulen = struct.unpack('!B', await reader.readexactly(1))[0]
        username = (await reader.readexactly(ulen)).decode()
        plen = struct.unpack('!B', await reader.readexactly(1))[0]
        password = (await reader.readexactly(plen)).decode()
        # 密码不正确
        if username != settings.SOCKS5_USERNAME or password != settings.SOCKS5_PASSWORD:
            writer.write(struct.pack('!BB', 0x01, 0x01))
            await writer.drain()
            return await self.close_writer(writer)
        # 认证通过
        writer.write(struct.pack('!BB', 0x01, 0x00))
        await writer.drain()

    async def handle_socks5_request(self,
                                    reader: StreamReader,
                                    writer: StreamWriter) -> Optional[tuple[StreamReader, StreamWriter]]:
        """
        处理 socks5 连接的请求阶段
        :param reader: StreamReader
        :param writer: StreamWriter
        :return: socks5 客户端使用的 tunnel (StreamReader, StreamWriter)
        """
        try:
            head = await reader.readexactly(3)
        except IncompleteReadError:
            await self.close_writer(writer)
            return
        version, cmd, _ = struct.unpack('!BBB', head)
        # 校验版本
        if version != self.SOCKS_VERSION:
            await self.close_writer(writer)
            return
        atyp = struct.unpack('!B', await reader.readexactly(1))[0]
        # IPV4
        if atyp == 0x01:
            dst_addr = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
        # Domain name
        elif atyp == 0x03:
            domain_length = ord(await reader.readexactly(1))
            dst_addr = (await reader.readexactly(domain_length)).decode()
        # IPV6
        elif atyp == 0x04:
            dst_addr = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(6))
        else:
            raise exceptions.UnknownTypeException('未知的类型: %s' % atyp)
        dst_port = struct.unpack('!H', await reader.readexactly(2))[0]
        # TODO: 暂时只支持 CONNECT 请求
        if cmd != 0x01:
            writer.write(struct.pack('!BBBBIH', self.SOCKS_VERSION, 0x07, 0x00, 0x01, 0x00, 0x00))
            await writer.drain()
            await self.close_writer(writer)
            return
        # 没有可用的 agent，则拒绝请求
        if not self.tunnel_map:
            logger.warning('no available agent')
            writer.write(struct.pack('!BBBBIH', self.SOCKS_VERSION, 0x09, 0x00, 0x01, 0x00, 0x00))
            await writer.drain()
            await self.close_writer(writer)
            return
        # 保存客户端
        await self.save_client(reader, writer)
        # 构造创建连接的请求数据
        id_bytes = await self.mk_id_bytes(reader, writer)
        data = struct.pack('!BB', 0x01, len(id_bytes)) + id_bytes
        data += struct.pack('!B', cmd)
        data += utils.transform_addr_port_to_bytes(dst_addr, dst_port)
        # TODO: 随机选择一个 agent，并发起创建连接的请求，暂时随机，后期增加多端口的方式选择不同的 agent
        tunnel_reader, tunnel_writer = random.choice(list(self.tunnel_map.values()))
        await self.send(tunnel_reader, tunnel_writer, data)
        # 返回当前 socks5 客户端使用的 tunnel
        return tunnel_reader, tunnel_writer

    async def handle_socks5_relay(self,
                                  reader: StreamReader,
                                  writer: StreamWriter,
                                  tunnel_reader: StreamReader,
                                  tunnel_writer: StreamWriter):
        """
        处理 socks5 的 relay 阶段
        :param reader: socks5 客户端的 StreamReader
        :param writer: socks5 客户端的 StreamWriter
        :param tunnel_reader: tunnel 客户端的 StreamReader
        :param tunnel_writer: tunnel 客户端的 StreamWriter
        :return:
        """
        id_bytes = await self.mk_id_bytes(reader, writer)
        while True:
            try:
                # 读取 socks5 客户端的内容
                req_data = await reader.read(settings.BUFFER_SIZE)
                # logger.debug(f'recv client data: {req_data}')
                # 如果没有数据，就中止了
                if not req_data:
                    break
                # 收到数据就发送到对应的 tunnel
                data = struct.pack('!BB', 0x02, len(id_bytes)) + id_bytes
                data += struct.pack('!H', len(req_data)) + req_data
                await self.send(tunnel_reader, tunnel_writer, data)
            except Exception as e:
                logger.exception(f'client recv error: {e}')
                break
        # 不管是请求完成还是发生异常，最后还是需要告诉 agent 要断开连接了
        await self.notice_client_closed(tunnel_reader, tunnel_writer, id_bytes)
        # 移除保存的映射
        await self.remove_client(reader, writer)
        # 关闭连接
        await self.close_writer(writer)

    # #################### 下面和 tunnel 服务相关 ####################
    async def start_tunnel_server(self):
        """开启 tunnel 服务"""
        self.tunnel_server = await self.call(
            backend_path=settings.CONNECTION_BACKEND,
            method='server_start',
            host=settings.TUNNEL_BIND_HOST,
            port=settings.TUNNEL_BIND_PORT,
            client_connected_cb=self.handle_tunnel_connect,
        )
        async with self.tunnel_server:
            logger.info(f'start tunnel server: {settings.TUNNEL_BIND_HOST}:{settings.TUNNEL_BIND_PORT}')
            await self.tunnel_server.serve_forever()

    async def handle_tunnel_connect(self, reader: StreamReader, writer: StreamWriter):
        """
        处理 tunnel 客户端的连接
        :param reader: StreamReader
        :param writer: StreamWriter
        :return:
        """
        logger.info(f'tunnel connected: {writer.get_extra_info("peername")}')
        result = await self.handle_tunnel_authenticate(reader, writer)
        # 如果认证失败，则不再继续
        if not result:
            return
        try:
            coros_or_futures = [
                self.handle_tunnel_cmd(reader, writer),
            ]
            if settings.PING_INTERVAL > 0:
                coros_or_futures += [
                    self.ping(reader, writer),
                    self.check_pong(reader, writer),
                ]
            await asyncio.gather(*coros_or_futures)
        except Exception as e:
            logger.exception(f'tunnel handle error: {e}')
            # 移除关系
            await self.remove_tunnel(reader, writer)
            # 则关闭连接
            await self.close_writer(writer)

    async def handle_tunnel_authenticate(self, reader: StreamReader, writer: StreamWriter) -> bool:
        """
        处理 tunnel 客户端的认证
        :param reader: StreamReader
        :param writer: StreamWriter
        :return: 认证结果
        """
        is_certify = await self.call(
            backend_path=settings.AUTHENTICATION_BACKEND,
            method='server',
            reader=reader,
            writer=writer,
        )
        # 认证成功
        if is_certify:
            await self.save_tunnel(reader, writer)
        # 认证失败
        else:
            await self.close_writer(writer)
        return is_certify

    async def ping(self, reader: StreamReader, writer: StreamWriter):
        """
        定时发送 ping 数据
        :param reader: StreamReader
        :param writer: StreamWriter
        :return:
        """
        data = struct.pack('!B', 0x05)
        while not writer.is_closing():
            await self.send(reader, writer, data)
            await asyncio.sleep(settings.PING_INTERVAL)

    async def check_pong(self, reader: StreamReader, writer: StreamWriter):
        """
        检查 tunnel 的 pong 响应是否正常
        :param reader: StreamReader
        :param writer: StreamWriter
        :return:
        """
        while not writer.is_closing():
            await asyncio.sleep(settings.PING_INTERVAL)
            pong_time = self.tunnel_ping_time.get(id(reader)) or 0
            # 如果上次 pong 的时间大于配置设置时间间隔的3倍，则认为超时了，对方已死
            if time.time() - pong_time > settings.PING_INTERVAL * 3:
                raise exceptions.PingPongTimeOutException

    async def handle_tunnel_cmd(self, reader: StreamReader, writer: StreamWriter):
        """
        处理 tunnel 回应的 cmd
        :param reader: StreamReader
        :param writer: StreamWriter
        :return:
        """
        # 处理 tunnel 发送过来的请求
        while True:
            data = await self.recv(reader, writer, 1)
            _type = struct.unpack('!B', data)[0]
            # logger.debug(f'type: {_type}')
            # 处理 connect 的回调
            if _type == 0x01:
                id_bytes = await self.get_id_bytes(reader, writer)
                rep = struct.unpack('!B', await self.recv(reader, writer, 1))[0]
                atyp, bnd_addr, bnd_port = await self.parse_socks5_addr_port(reader, writer)
                asyncio.ensure_future(self.after_tunnel_request(reader, writer, id_bytes, rep, atyp, bnd_addr, bnd_port))
            # 处理 relay 的回调
            elif _type == 0x02:
                id_bytes = await self.get_id_bytes(reader, writer)
                date_length = struct.unpack('!H', await self.recv(reader, writer, 2))[0]
                resp_data = await self.recv(reader, writer, date_length)
                asyncio.ensure_future(self.after_tunnel_relay(reader, writer, id_bytes, resp_data))
            # 服务端断开绑定连接（理论上不会进来）
            elif _type == 0x03:
                await self.recv(reader, writer, 1)
            # agent 客户端请求断开连接
            elif _type == 0x04:
                id_bytes = await self.get_id_bytes(reader, writer)
                asyncio.ensure_future(self.after_tunnel_close_connect(reader, writer, id_bytes))
            # agent 向服务端发送 ping 数据
            elif _type == 0x05:
                asyncio.ensure_future(self.handle_ping(reader, writer))
            # agent 向服务端回复的 pong 数据
            elif _type == 0x06:
                pass
            else:
                raise exceptions.UnknownCMDException()

    async def after_tunnel_request(self,
                                   reader: StreamReader,
                                   writer: StreamWriter,
                                   id_bytes: bytes,
                                   rep: int,
                                   atyp: int,
                                   bnd_addr: str,
                                   bnd_port: int):
        """
        处理创建连接后的回应
        :param reader: StreamReader
        :param writer: StreamWriter
        :param id_bytes: 客户端的 ID 标识
        :param rep: rep
        :param atyp: atyp
        :param bnd_addr:
        :param bnd_port:
        :return:
        """
        # client 如果不存在，通知 agent 关闭对应绑定的套接字
        cli_reader, cli_writer = await self.get_client(id_bytes)
        if not cli_reader:
            return await self.notice_client_closed(reader, writer, id_bytes)
        # 发送回应给到 socks5 客户端
        data = struct.pack('!BBB', self.SOCKS_VERSION, rep, 0x00)
        data += utils.transform_addr_port_to_bytes(bnd_addr, bnd_port)
        # logger.debug(f'send data: {data}')
        cli_writer.write(data)
        await cli_writer.drain()
        # 如果返回的 rep 不是成功的，则断开客户端的连接
        if rep != 0x00:
            return await self.close_writer(cli_writer)

    async def after_tunnel_relay(self, reader: StreamReader, writer: StreamWriter, id_bytes: bytes, resp_data: bytes):
        """
        处理 tunnel 的 relay 回应阶段
        :param reader: StreamReader
        :param writer: StreamWriter
        :param id_bytes:
        :param resp_data:
        :return:
        """
        # 如果没有 cli_reader，就不用再继续处理了
        cli_reader, cli_writer = await self.get_client(id_bytes)
        if not cli_reader:
            # 告诉 tunnel 断开连接
            return await self.notice_client_closed(reader, writer, id_bytes)
        cli_writer.write(resp_data)
        await cli_writer.drain()

    async def after_tunnel_close_connect(self, reader: StreamReader, writer: StreamWriter, id_bytes: bytes):
        """
        处理 tunnel 关闭连接的请求
        :param reader: StreamReader
        :param writer: StreamWriter
        :param id_bytes:
        :return:
        """
        cli_reader, cli_writer = await self.get_client(id_bytes)
        if not cli_reader:
            return
        await self.close_writer(cli_writer)

    async def handle_ping(self, reader: StreamReader, writer: StreamWriter):
        """
        处理 tunnel 的 ping
        :param reader: StreamReader
        :param writer: StreamWriter
        :return:
        """
        # 记录时间
        self.tunnel_ping_time[id(reader)] = time.time()
        # 回应 pong
        await self.send(reader, writer, struct.pack('!B', 0x06))

    # #################### 下面是一些通用方法 ####################
    async def save_client(self, reader: StreamReader, writer: StreamWriter):
        """
        保存 socks5 客户端的 streams
        :param reader: StreamReader
        :param writer: StreamWriter
        :return:
        """
        id_bytes = await self.mk_id_bytes(reader, writer)
        self.client_map[id_bytes] = (reader, writer)

    async def remove_client(self, reader: StreamReader, writer: StreamWriter):
        """
        移除 socks5 客户端的 streams
        :param reader: StreamReader
        :param writer: StreamWriter
        :return:
        """
        id_bytes = await self.mk_id_bytes(reader, writer)
        self.client_map.pop(id_bytes, None)

    async def get_client(self, id_bytes: bytes) -> tuple[Optional[StreamReader], Optional[StreamWriter]]:
        """
        获取对应的客户端的 streams
        :param id_bytes: ID 标识
        :return:
        """
        steams = self.client_map.get(id_bytes)
        # 没有找到对应的数据
        if not steams:
            return None, None
        # 找到了，但是连接关闭了
        if steams[0].at_eof() or steams[1].is_closing():
            self.client_map.pop(id_bytes, None)
            await self.close_writer(steams[1])
            return None, None
        return steams

    async def save_tunnel(self, reader: StreamReader, writer: StreamWriter):
        """
        保存 tunnel 的 streams
        :param reader: StreamReader
        :param writer: StreamWriter
        :return:
        """
        self.tunnel_map[id(reader)] = (reader, writer)
        self.tunnel_ping_time[id(reader)] = 0

    async def remove_tunnel(self, reader: StreamReader, writer: StreamWriter):
        """
        移除 tunnel 的内容
        :param reader: StreamReader
        :param writer: StreamWriter
        :return:
        """
        self.tunnel_map.pop(id(reader), None)
        self.tunnel_ping_time.pop(id(reader), None)

    async def notice_client_closed(self, reader: StreamReader, writer: StreamWriter, id_bytes: bytes):
        """
        通知 tunnel， socks5 客户端已经断开
        :param reader: tunnel 的 StreamReader
        :param writer: tunnel 的 StreamWriter
        :param id_bytes: socks5 客户端的 ID
        :return:
        """
        data = struct.pack('!BB', 0x03, len(id_bytes)) + id_bytes
        await self.send(reader, writer, data)


if __name__ == '__main__':
    server = Server()
    asyncio.run(server.start_server())
