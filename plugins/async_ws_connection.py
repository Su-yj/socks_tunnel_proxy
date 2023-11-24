import array
import asyncio
import base64
import hashlib
import io
import os
import re
import struct
import sys
from asyncio import StreamReader, StreamWriter
from typing import Union, Callable

from logger import logger
from plugins.async_connection import SocketConnection

try:
    # If wsaccel is available, use compiled routines to mask data.
    # wsaccel only provides around a 10% speed boost compared
    # to the websocket-client _mask() implementation.
    # Note that wsaccel is unmaintained.
    from wsaccel.xormask import XorMaskerSimple

    def _mask(_m, _d) -> bytes:
        return XorMaskerSimple(_m).process(_d)

except ImportError:
    # wsaccel is not available, use websocket-client _mask()
    native_byteorder = sys.byteorder

    def _mask(mask_value: array.array, data_value: array.array) -> bytes:
        datalen = len(data_value)
        int_data_value = int.from_bytes(data_value, native_byteorder)
        int_mask_value = int.from_bytes(mask_value * (datalen // 4) + mask_value[: datalen % 4], native_byteorder)
        return (int_data_value ^ int_mask_value).to_bytes(datalen, native_byteorder)


class WebSocketConnection(SocketConnection):
    """websocket方式进行连接"""
    WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

    # operation code values.
    OPCODE_CONT = 0x0
    OPCODE_TEXT = 0x1
    OPCODE_BINARY = 0x2
    OPCODE_CLOSE = 0x8
    OPCODE_PING = 0x9
    OPCODE_PONG = 0xa
    # available operation code value tuple
    OPCODES = (OPCODE_CONT, OPCODE_TEXT, OPCODE_BINARY, OPCODE_CLOSE, OPCODE_PING, OPCODE_PONG)

    # data length threshold.
    LENGTH_7 = 0x7e
    LENGTH_16 = 1 << 16
    LENGTH_63 = 1 << 63

    async def server_start(self, server, host: str, port: int, client_connected_cb: Callable, *args, **kwargs):
        async def ws_client_connected_cb(reader: StreamReader, writer: StreamWriter):
            try:
                data = await reader.read(1024)
                data = data.decode()
                if not data.endswith('\r\n'):
                    raise EOFError('line without CRLF')
                if not re.search(r'^GET .* HTTP/1\.1\r\n', data, re.I):
                    raise ValueError('unsupported HTTP method')
                if not re.search(r'Sec-WebSocket-Version: 13\r\n', data, re.I):
                    raise ValueError('Sec-WebSocket-Version not found')
                if not re.search(r'Connection: Upgrade\r\n', data, re.I):
                    raise ValueError('connection is not upgrade')
                if not re.search(r'Upgrade: websocket\r\n', data, re.I):
                    raise ValueError('upgrade is not websocket')
                results = re.findall(rf'Sec-WebSocket-Key: ([\w\W]+?)\r\n', data, re.I)
                if not results:
                    raise ValueError('websocket key not found')
                ws_key = results[0]
            # 如果校验不通过，则直接关闭连接
            except Exception as e:
                logger.warning(e)
                writer.close()
                return await writer.wait_closed()
            # 验证通过后，则向客户端发送可升级的回复
            raw_data = f'HTTP/1.1 101 Switching Protocols\r\n' \
                       f'Upgrade: websocket\r\n' \
                       f'Connection: Upgrade\r\n' \
                       f'Sec-WebSocket-Accept: {self.gen_access_key(ws_key)}\r\n' \
                       f'\r\n'
            writer.write(raw_data.encode())
            await writer.drain()
            await client_connected_cb(reader, writer)

        return await asyncio.start_server(ws_client_connected_cb, host=host, port=port)

    async def server_recv(self, server, reader: StreamReader, writer: StreamWriter, bufsize: int, exactly: bool = True,
                          *args, **kwargs):
        if not hasattr(server, '__payload_cache'):
            setattr(server, '__payload_cache', {})
        payload_cache = getattr(server, '__payload_cache', {})
        byte_stream = payload_cache.setdefault(reader, io.BytesIO())
        if exactly:
            data = await self.recv_strict(byte_stream=byte_stream, reader=reader, bufsize=bufsize)
        else:
            data = await self.recv(byte_stream=byte_stream, reader=reader, bufsize=bufsize)
        return data

    async def server_send(self, server, reader: StreamReader, writer: StreamWriter, data: Union[bytes, bytearray],
                          *args, **kwargs):
        payload = self.create_frame(data)
        writer.write(payload)
        await writer.drain()

    async def agent_start(self, server, host: str, port: int, *args, **kwargs) -> tuple[StreamReader, StreamWriter]:
        reader, writer = await super(WebSocketConnection, self).agent_start(server, host, port, *args, **kwargs)
        ws_key = self._create_sec_websocket_key()
        raw_data = f'GET ws://{host}:{port}/ HTTP/1.1\r\n' \
                   f'Host: {host}:{port}\r\n' \
                   f'Connection: Upgrade\r\n' \
                   f'Upgrade: websocket\r\n' \
                   f'Sec-WebSocket-Version: 13\r\n' \
                   f'Sec-WebSocket-Key: {ws_key}\r\n' \
                   f'\r\n'
        writer.write(raw_data.encode())
        await writer.drain()

        try:
            data = await reader.read(1024)
            data = data.decode()
            if not data.endswith('\r\n'):
                raise EOFError('line without CRLF')
            if not re.search(r'^HTTP/1\.1 101 Switching Protocols\r\n', data, re.I):
                raise ValueError('upgrade failed')
            if not re.search(rf'Sec-WebSocket-Accept: {re.escape(self.gen_access_key(ws_key))}\r\n', data, re.I):
                raise ValueError('accept key error')
        except Exception as e:
            logger.error(e)
            writer.close()
            await writer.wait_closed()
            raise e
        return reader, writer

    async def agent_recv(self, server, reader: StreamReader, writer: StreamWriter, bufsize: int, exactly: bool = True,
                         *args, **kwargs):
        if not hasattr(server, '__payload_cache'):
            setattr(server, '__payload_cache', {})
        payload_cache = getattr(server, '__payload_cache', {})
        byte_stream = payload_cache.setdefault(reader, io.BytesIO())
        if exactly:
            data = await self.recv_strict(byte_stream=byte_stream, reader=reader, bufsize=bufsize)
        else:
            data = await self.recv(byte_stream=byte_stream, reader=reader, bufsize=bufsize)
        return data

    async def agent_send(self, server, reader: StreamReader, writer: StreamWriter, data: Union[bytes, bytearray],
                         *args, **kwargs):
        payload = self.create_frame(data)
        writer.write(payload)
        await writer.drain()

    def gen_access_key(self, key: str) -> str:
        """
        生成 access key
        :param key:
        :return:
        """
        return base64.b64encode(hashlib.sha1((key + self.WS_GUID).encode()).digest()).decode()

    def _create_sec_websocket_key(self) -> str:
        """
        生成 Sec-WebSocket-Key
        :return:
        """
        randomness = os.urandom(16)
        return base64.encodebytes(randomness).decode('utf-8').strip()

    def get_mask_key(self, n: int) -> bytes:
        # 生成随机的32位掩码
        return os.urandom(n)

    def mask(self, mask_key: bytes, payload: bytes) -> bytes:
        """
        对数据进行掩码操作
        :param mask_key:
        :param payload:
        :return:
        """
        return _mask(array.array('B', mask_key), array.array('B', payload))

    def create_frame(self, payload: bytes, mask: bool = False, opcode: int = OPCODE_BINARY) -> bytes:
        """
        创建 websocket 的数据帧
        :param payload: 原始数据
        :param mask: 是否需要掩码
        :param opcode: 操作码
        :return:
        """
        payload_length = len(payload)
        if opcode not in self.OPCODES:
            raise ValueError("Invalid OPCODE")
        if payload_length >= self.LENGTH_63:
            raise ValueError("data is too long")

        frame_header = struct.pack('!B', 0x80 | opcode)
        if mask:
            mask_bit = 0x80
        else:
            mask_bit = 0
        if payload_length < self.LENGTH_7:
            frame_header += struct.pack("B", payload_length | mask_bit)
        elif payload_length < self.LENGTH_16:
            frame_header += struct.pack("!BH", 126 | mask_bit, payload_length)
        else:
            frame_header += struct.pack("!BQ", 127 | mask_bit, payload_length)

        if mask:
            mask_key = self.get_mask_key(4)
            frame_header += mask_key
            return frame_header + self.mask(mask_key, payload)
        else:
            return frame_header + payload

    async def recv_frame(self, reader: StreamReader):
        """
        接受 ws 的帧数据
        :param reader:
        :return:
        """
        header = await reader.readexactly(2)
        b1, b2 = struct.unpack('!BB', header)
        fin = b1 >> 7 & 1
        rsv1 = b1 >> 6 & 1
        rsv2 = b1 >> 5 & 1
        rsv3 = b1 >> 4 & 1
        opcode = b1 & 0xf
        has_mask = b2 >> 7 & 1
        length_bits = b2 & 0x7f
        if length_bits == 0x7e:
            v = await reader.readexactly(2)
            payload_length = struct.unpack('!H', v)[0]
        elif length_bits == 0x7f:
            v = await reader.readexactly(8)
            payload_length = struct.unpack('!Q', v)[0]
        else:
            payload_length = length_bits
        mask = b''
        if has_mask:
            mask = await reader.readexactly(4)
        payload = await reader.readexactly(payload_length)
        if has_mask:
            payload = self.mask(mask, payload)
        return fin, opcode, payload

    async def write_payload(self, byte_stream: io.BytesIO, reader: StreamReader):
        """
        写入 payload 数据到 byte_stream
        :param byte_stream:
        :param reader:
        :return:
        """
        # 如果 byte_stream 当前的指针不是在最后，就不用从 reader 中读取数据了
        if len(byte_stream.getbuffer()) != byte_stream.tell():
            return
        # 重置 byte_stream
        byte_stream.truncate(0)
        byte_stream.seek(0)
        # 重新获取数据
        fin, opcode, payload = await self.recv_frame(reader)
        byte_stream.write(payload)
        byte_stream.seek(0)

    async def recv(self, byte_stream: io.BytesIO, reader: StreamReader, bufsize: int):
        """
        接收数据
        :param byte_stream:
        :param reader:
        :param bufsize:
        :return:
        """
        await self.write_payload(byte_stream=byte_stream, reader=reader)
        return byte_stream.read(bufsize)

    async def recv_strict(self, byte_stream: io.BytesIO, reader: StreamReader, bufsize: int):
        """
        严格接收数据
        :param byte_stream:
        :param reader:
        :param bufsize:
        :return:
        """
        data = b''
        if len(data) < bufsize:
            await self.write_payload(byte_stream=byte_stream, reader=reader)
            data += byte_stream.read(bufsize - len(data))
        return data
