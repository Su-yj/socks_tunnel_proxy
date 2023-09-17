import socket
import time
from typing import Union

import settings
import utils
from logger import logger


class BaseConnection(object):
    def __init__(self):
        self.retry = 0

    def server_start(self, server, host: str, port: int, *args, **kwargs) -> socket.socket:
        """
        服务端启动服务
        :param server: 当前的服务
        :param host:
        :param port:
        :return:
        """
        raise NotImplementedError()

    def server_accept(self, server, sock: socket.socket, *args, **kwargs) -> socket.socket:
        """
        服务端的 tunnel 接收到连接请求
        :param server: 当前的服务
        :param sock: 服务端的 tunnel 套接字
        :return:
        """
        conn, addr = sock.accept()
        logger.info(f'accept agent client [{conn}] from {addr}')
        return conn

    def server_recv(self, server, sock: socket.socket, bufsize: int, *args, **kwargs):
        """
        服务端接收 tunnel 客户端请求的处理过程
        :param server: 当前服务
        :param sock: tunnel 服务的套接字
        :param bufsize: 接收的长度
        :param args:
        :param kwargs:
        :return:
        """
        raise NotImplementedError()

    def server_send(self, server, sock: socket.socket, data: Union[bytes, bytearray], *args, **kwargs):
        """
        服务端的 tunnel 发送数据到客户端
        :param server: 当前的服务
        :param sock: tunnel 服务的套接字
        :param data: 需要发送的数据
        :param args:
        :param kwargs:
        :return:
        """
        raise NotImplementedError()

    def agent_start(self, server, host: str, port: int, *args, **kwargs) -> socket.socket:
        """
        agent 端
        :param server: 当前的服务
        :param host:
        :param port:
        :return:
        """
        raise NotImplementedError()

    def agent_recv(self, server, sock: socket.socket, bufsize: int, *args, **kwargs):
        """
        agent 端接收数据处理
        :param server: 当前的服务
        :param sock: agent 的套接字
        :param bufsize: 接收的长度
        :param args:
        :param kwargs:
        :return:
        """
        raise NotImplementedError()

    def agent_send(self, server, sock: socket.socket, data: Union[bytes, bytearray], *args, **kwargs):
        """
        agent 端发送数据
        :param server: 当前的服务
        :param sock: agent 的套接字
        :param data: 待发送的数据
        :param args:
        :param kwargs:
        :return:
        """
        raise NotImplementedError()


class SocketConnection(BaseConnection):
    """套接字方式连接"""

    def server_start(self, server, host: str, port: int, *args, **kwargs) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(128)
        sock.setblocking(False)
        return sock

    def server_recv(self, server, sock: socket.socket, bufsize: int, *args, **kwargs):
        return sock.recv(bufsize)

    def server_send(self, server, sock: socket.socket, data: Union[bytes, bytearray], *args, **kwargs):
        return sock.send(data)

    def agent_start(self, server, host: str, port: int, *args, **kwargs) -> socket.socket:
        sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
        except ConnectionRefusedError:
            sock.close()
            if (settings.TUNNEL_SERVER_RETRY > 0 and self.retry < settings.TUNNEL_SERVER_RETRY) or \
                    settings.TUNNEL_SERVER_RETRY <= 0:
                time.sleep(settings.TUNNEL_SERVER_CONNECT_INTERVAL)
                self.retry += 1
                logger.warning(f'reconnect to server: {self.retry} times')
                return self.agent_start(server, host, port, *args, **kwargs)
            raise
        utils.set_keepalive(sock)
        return sock

    def agent_recv(self, server, sock: socket.socket, bufsize: int, *args, **kwargs):
        return sock.recv(bufsize)

    def agent_send(self, server, sock: socket.socket, data: Union[bytes, bytearray], *args, **kwargs):
        return sock.send(data)
