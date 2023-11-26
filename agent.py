import selectors
import socket
import struct
from typing import Optional

import exceptions
import settings
import utils
from base import BaseServer
from logger import logger


class Agent(BaseServer):
    _TYPE = 'agent'

    def __init__(self):
        self.selector = selectors.DefaultSelector()
        self.agent_socket = None
        self.retry = 0
        self.cli_remote_map: dict[bytes, socket.socket] = {}

    @logger.catch
    def run(self):
        self.start_agent()
        while True:
            try:
                events = self.selector.select()
                for key, _ in events:
                    callback = key.data[0]
                    callback(key.fileobj, *key.data[1:])
            except KeyboardInterrupt:
                self.close()
                logger.info('Bye Bye!')
                break

    def close(self):
        self.selector.close()
        self.agent_socket.close()

    # #################### 下面是通用方法 ####################
    def save_map(self, remote: socket.socket, cli_info: bytes):
        """
        保存 remote 和 client 的映射
        :param remote: 目标地址的套接字
        :param cli_info: 代理客户端的 16 进制内存地址
        :return:
        """
        self.cli_remote_map[cli_info] = remote

    def delete_map(self, cli_info: bytes = None):
        """
        删除 remote 和 client 的映射
        :param cli_info: 代理客户端的 16 进制内存地址
        :return:
        """
        return self.cli_remote_map.pop(cli_info, None)

    def get_remote(self, cli_info: bytes) -> Optional[socket.socket]:
        """
        通过代理客户端的地址获取 remote 的套接字
        :param cli_info: 代理客户端的 16 进制内存地址
        :return: 目标地址的套接字
        """
        remote = self.cli_remote_map.get(cli_info)
        if remote and remote.fileno() == -1:
            self.cli_remote_map.pop(cli_info, None)
            self.selector.unregister(remote)
            remote.close()
            return
        return remote

    def close_sock(self, sock: socket.socket):
        """
        关闭套接字的连接
        :param sock: 待关闭的套接字
        :return:
        """
        logger.debug(f'close connect: {sock}')
        try:
            self.selector.unregister(sock)
        except KeyError:
            logger.warning(f'套接字未注册到监听中：{sock}')
        return sock.close()

    # #################### agent 客户端的逻辑处理 ####################
    def start_agent(self):
        logger.info('start agent server')
        self.agent_socket = self.call(
            backend_path=settings.CONNECTION_BACKEND,
            method='agent_start',
            host=settings.TUNNEL_SERVER_HOST,
            port=settings.TUNNEL_SERVER_PORT,
        )
        utils.set_keepalive(self.agent_socket)
        if not self.call(
                backend_path=settings.AUTHENTICATION_BACKEND,
                method='agent',
                sock=self.agent_socket,
        ):
            self.agent_socket.close()
            raise exceptions.AuthenticationFailedException()
        self.agent_socket.setblocking(False)
        self.selector.register(self.agent_socket, selectors.EVENT_READ, (self.handle_server_cmd,))
        # 重置重试的次数
        self.retry = 0
        logger.info('tunnel server connected')

    def handle_server_cmd(self, agent_socket: socket.socket):
        """
        接受处理服务端的指令
        :param agent_socket: agent 客户端的套接字
        :return:
        """
        try:
            data = self.recv(agent_socket, 1)
        except ConnectionResetError:
            data = None
        if not data:
            logger.warning(f'tunnel server disconnected')
            # 注销之前的监听
            self.selector.unregister(agent_socket)
            # 关闭套接字
            agent_socket.close()
            # 重新创建一个新的连接
            return self.start_agent()
        _type = struct.unpack('!B', data)[0]
        if _type == 0x01:
            return self.create_connect(agent_socket)
        elif _type == 0x02:
            return self.remote_relay(agent_socket)
        elif _type == 0x03:
            return self.close_connect(agent_socket)
        elif _type == 0x04:
            # 虽然这里理论上不会进入，但如果进入了，则按照协议再取一个字节，防止后面的数据乱了
            return agent_socket.recv(1)
        else:
            raise exceptions.UnknownCMDException()

    def create_connect(self, agent_socket: socket.socket):
        """
        创建新的连接
        :param agent_socket: agent 客户端的套接字
        :return:
        """
        memory_bytes = self.get_memory_bytes(agent_socket)
        cmd = struct.unpack('!B', self.recv(agent_socket, 1))
        atyp, dst_addr, dst_port = self.parse_socks5_addr_port(agent_socket)

        if atyp == 0x01 or atyp == 0x03:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif atyp == 0x04:
            remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            raise exceptions.UnknownTypeException()

        remote.setblocking(False)
        self.selector.register(remote, selectors.EVENT_WRITE, (self.create_connect_cb, agent_socket, memory_bytes))
        try:
            logger.info(f'create remote: {(dst_addr, dst_port)}')
            remote.connect((dst_addr, dst_port))
        except BlockingIOError:
            pass

    def create_connect_cb(self, remote: socket.socket, agent_socket: socket.socket, memory_bytes: bytes):
        self.selector.unregister(remote)
        try:
            remote.getpeername()
        # 如果拿不到，说明这个连接未建立，需要关闭
        except:
            remote.close()
            data = struct.pack('!B', 0x01)
            data += struct.pack('!B', len(memory_bytes)) + memory_bytes
            data += struct.pack('!BBIH', 0x05, 0x01, 0x00, 0x00)
            return self.send(agent_socket, data)

        data = struct.pack('!B', 0x01)
        data += struct.pack('!B', len(memory_bytes)) + memory_bytes
        data += struct.pack('!BBIH', 0x00, 0x01, 0x00, 0x00)
        self.send(agent_socket, data)
        self.save_map(remote, memory_bytes)
        self.selector.register(remote, selectors.EVENT_READ, (self.handle_remote_recv, memory_bytes))

    def remote_relay(self, agent_socket: socket.socket):
        """
        处理 relay 阶段的数据
        :param agent_socket: agent 客户端的套接字
        :return:
        """
        memory_bytes = self.get_memory_bytes(agent_socket)
        length = struct.unpack('!H', self.recv(agent_socket, 2))[0]
        req_data = self.recv(agent_socket, length)
        remote = self.get_remote(memory_bytes)
        if not remote:
            # 告诉服务端 remote 的连接断开了
            return self.send_close_client(memory_bytes=memory_bytes)
        remote.send(req_data)

    def close_connect(self, agent_socket: socket.socket):
        """
        关闭 remote 的连接
        :param agent_socket: agent 客户端的套接字
        :return:
        """
        memory_bytes = self.get_memory_bytes(agent_socket)
        remote = self.delete_map(cli_info=memory_bytes)
        if not remote:
            return
        self.close_sock(remote)

    def handle_remote_recv(self, remote: socket.socket, memory_bytes: bytes):
        """处理远程服务发送过来的消息"""
        resp_data = remote.recv(settings.BUFFER_SIZE)
        if not resp_data:
            # 删除映射
            self.delete_map(cli_info=memory_bytes)
            # 通知服务端连接断开了
            self.send_close_client(memory_bytes=memory_bytes)
            return self.close_sock(remote)

        data = struct.pack('!B', 0x02)
        data += struct.pack('!B', len(memory_bytes)) + memory_bytes
        data += struct.pack('!H', len(resp_data))
        data += resp_data
        self.send(self.agent_socket, data)

    def send_close_client(self, memory_bytes: bytes):
        data = struct.pack('!B', 0x04)
        data += struct.pack('!B', len(memory_bytes)) + memory_bytes
        self.send(self.agent_socket, data)


if __name__ == '__main__':
    agent = Agent()
    agent.run()
