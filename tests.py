import selectors
import socket
import struct
import threading
import time
import unittest

import requests

from agent import Agent
from server import Server


class SocketTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.host = 'localhost'
        self.port = 8888

        self.server_thread = threading.Thread(target=self.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        # 等待服务器启动
        time.sleep(0.1)

    def tearDown(self) -> None:
        self.s.close()

    def start_server(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.host, self.port))
        self.s.listen()
        client_socket, client_addr = self.s.accept()
        print('服务端收到新请求', client_addr)
        message = client_socket.recv(1024)
        print('服务端收到消息：', message)
        client_socket.sendall(struct.pack('!BB', 5, 0xFF))

    def test_01(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))
        self.client_socket.sendall(b'hello')
        message = self.client_socket.recv(1024)
        print('客户端收到消息：', message)
        self.client_socket.close()

    def test_02(self):
        proxy = f'socks5://{self.host}:{self.port}'
        try:
            requests.get('http://www.baidu.com', proxies={'http': proxy, 'https': proxy})
        except:
            pass

    def test_03(self):
        proxy = f'socks5://root:root@{self.host}:{self.port}'
        try:
            requests.get('http://www.baidu.com', proxies={'http': proxy, 'https': proxy})
        except:
            pass

    def test_04(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('www.baidu.com', 80))
        print(sock.send(b'xxx'))

    def test_05(self):
        conn = socket.create_connection(('www.baidu.com', 80))
        conn.sendall(b'GET / HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n')
        print(conn.recv(1024))
        conn.close()


class MultiSocketTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.host = 'localhost'
        self.port = 8888
        self.server_thread = threading.Thread(target=self.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()

    def start_server(self):
        server_socket = socket.create_server((self.host, self.port))
        conn, addr = server_socket.accept()
        print(conn.getpeername())
        time.sleep(1)
        for i in range(10):
            print(conn.recv(1000))

    def send(self, i):
        self.client_socket.send(i.encode()*1000)

    def test_01(self):
        self.client_socket = socket.create_connection((self.host, self.port))
        thread_list = []
        for i in range(10):
            send_thread = threading.Thread(target=self.send, args=str(i))
            send_thread.daemon = True
            thread_list.append(send_thread)
        for i in thread_list:
            i.start()
        time.sleep(3)

    def test_02(self):
        def server():
            # sock = socket.create_server(('', 8888), family=socket.AF_INET6, dualstack_ipv6=True)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
            sock.bind(('::', 9000))
            sock.listen(5)
            print('listen')
            for i in range(2):
                client_socket, client_addr = sock.accept()
                print(client_addr)
                print(client_socket.getpeername())
                print(client_socket.getsockname())
                print(client_socket.recv(100))
                client_socket.close()
            sock.close()
            print('close')

        server_thread = threading.Thread(target=server)
        server_thread.daemon = True
        server_thread.start()
        time.sleep(0.1)

        client_sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock1.connect(('127.0.0.1', 9000))
        client_sock1.send(b'aaaaa')
        time.sleep(200)

        client_sock2 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        client_sock2.connect(('::1', 9000))
        client_sock2.send(b'bbbbb')
        time.sleep(0.2)

        client_sock1.close()
        client_sock2.close()

    def test_03(self):
        def read(conn, mask):
            print(mask)
            data = conn.recv(100)
            print(data)
            if not data:
                selector.unregister(conn)
                conn.close()

        selector = selectors.DefaultSelector()

        def server():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # sock.setblocking(False)
            sock.bind(('localhost', 9000))
            sock.listen(5)
            print('listen')
            conn, client_addr = sock.accept()
            selector.register(conn, selectors.EVENT_READ, read)
            while True:
                try:
                    events = selector.select()
                    print(events)
                    for key, mask in events:
                        callback = key.data
                        callback(key.fileobj, mask)
                except OSError:
                    break
            sock.close()
            print('close')

        server_thread = threading.Thread(target=server)
        server_thread.daemon = True
        server_thread.start()
        time.sleep(0.1)

        client_socket = socket.create_connection(('localhost', 9000))
        client_socket.send(b'1' * 1000)
        client_socket.close()
        time.sleep(10)


class Socks5TestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.proxy = 'socks5://localhost:8888'

    def start_server(self):
        def start():
            self.server = Server()
            self.server.run()

        self.server_thread = threading.Thread(target=start)
        self.server_thread.daemon = True
        self.server_thread.start()

    def start_agent(self):
        def start():
            self.agent = Agent()
            self.agent.run()

        self.agent_thread = threading.Thread(target=start)
        self.agent_thread.daemon = True
        self.agent_thread.start()

    def test_01(self):
        self.start_server()
        self.start_agent()
        time.sleep(0.1)
        response = requests.get('http://www.baidu.com', proxies={'http': self.proxy, 'https': self.proxy})
        self.assertEqual(response.status_code, 200)
        response = requests.get('https://www.baidu.com', proxies={'http': self.proxy, 'https': self.proxy})
        self.assertEqual(response.status_code, 200)

    def test_02(self):
        self.start_server()
        self.start_agent()
        time.sleep(0.1)

        result = []
        thread_list = []

        def test_multi_thread():
            response = requests.get('https://www.baidu.com', proxies={'http': self.proxy, 'https': self.proxy})
            self.assertEqual(response.status_code, 200)
            result.append(response.text)

        for i in range(100):
            test_thread = threading.Thread(target=test_multi_thread)
            test_thread.daemon = True
            thread_list.append(test_thread)
            test_thread.start()

        for i in thread_list:
            i.join()

        self.assertEqual(len(result), 100)
        for i, r in enumerate(result):
            if i == 0:
                continue
            self.assertEqual(result[0], result[i])
