import socket
import struct


class BaseAuthentication(object):
    def server(self, server, sock: socket.socket, *args, **kwargs) -> bool:
        """
        服务端
        :param server: 当前的服务
        :param sock: agent 与服务端创建连接后的套接字
        :return: auth result
        """
        raise NotImplementedError()

    def agent(self, server, sock: socket.socket, *args, **kwargs) -> bool:
        """
        agent 端
        :param server: 当前的服务
        :param sock: agent 服务的套接字
        :return: auth result
        """
        raise NotImplementedError()


class AnonymousAuthentication(BaseAuthentication):
    """无认证"""

    def server(self, server, sock: socket.socket, *args, **kwargs):
        server.recv(sock, 1024)
        server.send(sock, struct.pack('!B', 0x00))
        return True

    def agent(self, server, sock: socket.socket, *args, **kwargs):
        server.send(sock, b'hello')
        result = struct.unpack('!B', server.recv(sock, 1))[0]
        return result == 0x00
