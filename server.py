import random
import selectors
import socket
import struct
from typing import List, Optional

import exceptions
import settings
import utils
from base import BaseServer
from logger import logger


class Server(BaseServer):
    """Socks5 Proxy Server"""
    _TYPE = 'server'
    # socks proxy version
    SOCKS_VERSION = 0x05

    def __init__(self):
        self.selector = selectors.DefaultSelector()
        # socks5 server socket
        self.socks5_socket = None
        # tunnel server socket
        self.tunnel_socket = None
        # socket map of proxy client
        self.client_map: dict[bytes, socket.socket] = {}
        # socket map of agent client
        self.agent_map: dict[int, socket.socket] = {}

    @logger.catch
    def run(self):
        self.start_socks5_server()
        self.start_tunnel_socket()
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
        self.socks5_socket.close()
        self.tunnel_socket.close()

    # #################### 下面是一些通用方法 ####################
    def start_server(self, addr: str, port: int) -> socket.socket:
        """
        开启服务
        :param addr: 绑定地址
        :param port: 绑定端口
        :return: 绑定的 socket 套接字
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((addr, port))
        server_socket.listen(128)
        server_socket.setblocking(False)
        return server_socket

    def save_client(self, sock: socket.socket) -> None:
        """
        保存代理客户端的套接字映射
        :param sock: 代理客户端的套接字
        :return:
        """
        key = self.int2bytes(id(sock))
        self.client_map[key] = sock

    def save_agent(self, sock: socket.socket) -> None:
        """
        保存 agent 客户端的套接字映射
        :param sock: agent 客户端的套接字
        :return:
        """
        self.agent_map[id(sock)] = sock

    def get_client(self, value: bytes) -> Optional[socket.socket]:
        """
        根据内存地址获取代理客户端的套接字对象
        :param value: 内存地址的 16 进制值
        :return: 代理客户端的套接字
        """
        client = self.client_map.get(value)
        if not client:
            return
        if client.fileno() == -1:
            logger.info(f'client was closed: {client}')
            self.client_map.pop(value, None)
            return
        return client

    def get_agent(self, value: bytes) -> Optional[socket.socket]:
        """
        根据内存地址获取 agent 客户端的套接字对象
        :param value: 存地址的 16 进制值
        :return: agent 客户端的套接字
        """
        memory_addr = utils.bytes2int(value)
        agent = self.agent_map.get(memory_addr)
        if not agent:
            return
        if agent.fileno() == -1:
            logger.info(f'agent was closed: {agent}')
            self.agent_map.pop(memory_addr, None)
            return
        return agent

    def close_bnd_socket(self, agent: socket.socket, client: socket.socket):
        """
        关闭代理客户端对应 agent 服务中的 remote 套接字
        :param agent: agent 客户端
        :param client: 代理客户端的套接字
        :return: 
        """
        data = struct.pack('!B', 0x03)
        data += self.sock2send_data(client)
        self.send(agent, data)

    def close_client(self, sock: socket.socket):
        """
        关闭代理客户端的套接字
        :param sock: 代理客户端的套接字
        :return: 
        """
        key = self.int2bytes(id(sock))
        self.client_map.pop(key, None)
        return self.close_sock(sock)

    def close_agent(self, sock: socket.socket):
        """
        关闭 agent 的套接字
        :param sock: agent 客户端的套接字
        :return: 
        """
        self.agent_map.pop(id(sock), None)
        return self.close_sock(sock)

    def close_sock(self, sock: socket.socket):
        """断开代理客户端的连接"""
        try:
            self.selector.unregister(sock)
        except KeyError:
            logger.warning(f'套接字未注册到监听中：{sock}')
        return sock.close()

    # #################### 下面是与代理服务相关 ####################
    def start_socks5_server(self):
        """开启 socks5 代理服务"""
        self.socks5_socket = self.start_server(settings.SOCKS5_BIND_HOST, settings.SOCKS5_BIND_PORT)
        logger.info(f'start socks5 server: {settings.SOCKS5_BIND_HOST}:{settings.SOCKS5_BIND_PORT}')
        self.selector.register(self.socks5_socket, selectors.EVENT_READ, (self.accept_proxy_client,))

    def accept_proxy_client(self, socks5_socket: socket.socket):
        """
        socks5 服务接收到新代理连接的处理
        :param socks5_socket: socks5 服务的套接字
        :return:
        """
        conn, addr = socks5_socket.accept()
        logger.debug(f'accept proxy client [{conn}] from {addr}')
        conn.setblocking(False)
        self.selector.register(conn, selectors.EVENT_READ, (self.parse_method_payload,))

    def parse_method_payload(self, client: socket.socket):
        """
        socks5 代理连接协商阶段
        :param client: 代理客户端的套接字
        :return:
        """
        header = client.recv(2)
        if not header:
            return self.close_sock(client)
        version, nmethods = struct.unpack('!BB', header)
        # 校验版本
        if version != self.SOCKS_VERSION or nmethods <= 0x00:
            client.send(struct.pack('!BB', self.SOCKS_VERSION, 0xFF))
            return self.close_sock(client)
        # 如果需要验证，检查客户端发送过来的验证方法是什么
        methods = self.get_available_methods(client, nmethods)
        # 如果允许匿名，直接告诉客户端即可
        if settings.SOCKS5_ALLOW_ANONYMOUS:
            client.send(struct.pack('!BB', self.SOCKS_VERSION, 0x00))
            # 注销监听
            self.selector.unregister(client)
            # 添加新的监听，处理请求阶段
            self.selector.register(client, selectors.EVENT_READ, (self.parse_request_payload,))
            return
        # 需要账号密码认证
        if 0x02 not in methods:
            return self.close_sock(client)
        client.send(struct.pack('!BB', self.SOCKS_VERSION, 0x02))
        # 注销旧的监听
        self.selector.unregister(client)
        # 添加新的监听，处理账号密码认证
        self.selector.register(client, selectors.EVENT_READ, (self.parse_auth_payload,))

    def get_available_methods(self, client: socket.socket, n: int) -> List[int]:
        """
        获取可用的方法
        :param client: 代理客户端的套接字
        :param n: 数量
        :return:
        """
        methods = []
        for i in range(n):
            methods.append(ord(client.recv(1)))
        return methods

    def parse_auth_payload(self, client: socket.socket):
        """
        认证 socks5 的账号密码
        :param client: 代理客户端的套接字
        :return:
        """
        # 校验版本
        version = client.recv(1)
        if not version:
            return self.close_sock(client)
        # 账号密码认证
        ulen = struct.unpack('!B', client.recv(1))[0]
        username = client.recv(ulen).decode()
        plen = struct.unpack('!B', client.recv(1))[0]
        password = client.recv(plen).decode()
        if username != settings.SOCKS5_USERNAME or password != settings.SOCKS5_PASSWORD:
            client.send(struct.pack('!BB', self.SOCKS_VERSION, 0xFF))
            return self.close_sock(client)
        client.send(struct.pack('!BB', self.SOCKS_VERSION, 0x00))
        # 注销监听
        self.selector.unregister(client)
        # 添加新的监听，处理请求阶段
        self.selector.register(client, selectors.EVENT_READ, (self.parse_request_payload,))

    def parse_request_payload(self, client: socket.socket):
        """
        socks5 代理请求阶段处理
        :param client: 代理客户端的套接字
        :return:
        """
        head = client.recv(3)
        if not head:
            return self.close_sock(client)
        version, cmd, _ = struct.unpack('!BBB', head)
        # 校验版本
        if version != self.SOCKS_VERSION:
            return self.close_sock(client)
        try:
            atyp, dst_addr, dst_port = utils.parse_socks5_addr_port(client)
        except Exception as e:
            logger.exception(e)
            return self.close_sock(client)
        # TODO: 检查 CMD 类型，暂时只实现 CONNECT 请求
        if cmd != 0x01:
            client.send(struct.pack('!BBBBIH', self.SOCKS_VERSION, 0x07, 0x00, 0x01, 0x00, 0x00))
            return self.close_sock(client)
        # 如果没有可用的 agent，则拒绝请求
        if not self.agent_map:
            logger.info(f'no agent connected')
            client.send(struct.pack('!BBBBIH', self.SOCKS_VERSION, 0x09, 0x00, 0x01, 0x00, 0x00))
            return self.close_sock(client)
        self.save_client(client)

        # 向 agent 发起创建连接请求
        data = struct.pack('!B', 0x01)
        data += self.sock2send_data(client)
        data += struct.pack('!B', cmd)
        data += utils.transform_addr_port_to_bytes(dst_addr, dst_port)
        # TODO：后期增加多端口或多路由方式选择不同的 agent
        agent_client = random.choice(list(self.agent_map.values()))
        self.send(agent_client, data)

    def parse_relay_payload(self, client: socket.socket, agent: socket.socket):
        """处理 relay 阶段"""
        if client.fileno() == -1:
            return
        if agent.fileno() == -1:
            logger.debug('agent was closed')
            return self.close_client(client)
        req_data = client.recv(settings.BUFFER_SIZE)
        # 如果没有数据
        if not req_data:
            # 通知 agent 连接断开了
            self.close_bnd_socket(agent, client)
            # 断开监听
            return self.close_client(client)
        data = struct.pack('!B', 0x02)
        data += self.sock2send_data(client)
        data += struct.pack('!H', len(req_data)) + req_data
        self.send(agent, data)

    # #################### 下面是与 agent 服务相关 ####################
    def start_tunnel_socket(self):
        """开启 tunnel 的服务"""
        self.tunnel_socket = self.call(
            backend_path=settings.CONNECTION_BACKEND,
            method='server_start',
            host=settings.TUNNEL_BIND_HOST,
            port=settings.TUNNEL_BIND_PORT
        )
        logger.info(f'start tunnel server: {settings.TUNNEL_BIND_HOST}:{settings.TUNNEL_BIND_PORT}')
        self.selector.register(self.tunnel_socket, selectors.EVENT_READ, (self.accept_agent_client,))

    def accept_agent_client(self, tunnel_socket: socket.socket):
        """接收 agent 的请求"""
        conn = self.call(
            backend_path=settings.CONNECTION_BACKEND,
            method='server_accept',
            sock=tunnel_socket,
        )
        conn.setblocking(False)
        utils.set_keepalive(conn)
        self.selector.register(conn, selectors.EVENT_READ, (self.start_agent_client,))
        
    def start_agent_client(self, agent: socket.socket):
        """开启 agent 连接"""
        if not self.call(
                backend_path=settings.AUTHENTICATION_BACKEND,
                method='server',
                sock=agent,
        ):
            return self.close_sock(agent)
        self.save_agent(agent)
        self.selector.unregister(agent)
        self.selector.register(agent, selectors.EVENT_READ, (self.handle_agent_recv,))

    def handle_agent_recv(self, agent: socket.socket):
        """处理 agent 客户端发送的请求"""
        try:
            data = self.recv(agent, 1)
        except ConnectionResetError:
            data = None
        if not data:
            logger.info(f'agent was closed: {agent}')
            return self.close_agent(agent)
        _type = struct.unpack('!B', data)[0]
        if _type == 0x01:
            return self.handle_proxy_response(agent)
        elif _type == 0x02:
            return self.handle_agent_relay(agent)
        elif _type == 0x03:
            # 虽然这里理论上不会进入，但如果进入了，则按照协议再取一个字节，防止后面的数据乱了
            return self.recv(agent, 1)
        elif _type == 0x04:
            return self.handle_bnd_close(agent)
        else:
            raise exceptions.UnknownCMDException()

    def handle_proxy_response(self, agent: socket.socket):
        """处理 agent 转发的请求阶段"""
        memory_bytes = self.get_memory_bytes(agent)
        rep = struct.unpack('!B', self.recv(agent, 1))[0]
        atyp, bnd_addr, bnd_port = self.parse_socks5_addr_port(agent)
        # client 如果不存在，通知 agent 关闭对应绑定的套接字
        client = self.get_client(memory_bytes)
        if not client:
            logger.debug(f'client not found')
            return self.close_agent_bnd(agent, memory_bytes)
        data = struct.pack('!BBB', self.SOCKS_VERSION, rep, 0x00)
        data += utils.transform_addr_port_to_bytes(bnd_addr, bnd_port)
        client.send(data)
        # 如果返回的 rep 不是成功的，则断开客户端的连接
        if rep != 0x00:
            return self.close_client(client)
        # 注销上次 client 的监听
        self.selector.unregister(client)
        # 添加新的监听
        self.selector.register(client, selectors.EVENT_READ, (self.parse_relay_payload, agent))

    def handle_agent_relay(self, agent: socket.socket):
        """处理 agent 的 relay 转发"""
        memory_bytes = self.get_memory_bytes(agent)
        length = struct.unpack('!H', self.recv(agent, 2))[0]
        resp_data = self.recv(agent, length)
        # client 如果不存在，通知 agent 关闭对应绑定的套接字
        client = self.get_client(memory_bytes)
        if not client:
            logger.debug(f'client not found')
            return self.close_agent_bnd(agent, memory_bytes)
        client.send(resp_data)

    def handle_bnd_close(self, agent: socket.socket):
        """agent 绑定的套接字被关闭了的处理"""
        memory_bytes = self.get_memory_bytes(agent)
        client = self.get_client(memory_bytes)
        if not client:
            logger.debug(f'client not found')
            return
        return self.close_client(client)

    def close_agent_bnd(self, agent: socket.socket, memory_bytes: bytes):
        """通知 agent 关闭远端的套接字"""
        data = struct.pack('!BB', 0x03, len(memory_bytes)) + memory_bytes
        self.send(agent, data)


if __name__ == '__main__':
    server = Server()
    server.run()
