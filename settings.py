import os

# #################### Public Config ####################
# packet forwarding size（1024~4096）
BUFFER_SIZE = int(os.getenv('BUFFER_SIZE', 1024))
# log level (DEBUG | INFO | WARNING | ERROR | CRITICAL)
LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')
# connection backends
CONNECTION_BACKEND = os.getenv('CONNECTION_BACKEND', 'plugins.async_ws_connection.WebSocketConnection')
# authentication backend
AUTHENTICATION_BACKEND = os.getenv('AUTHENTICATION_BACKEND', 'plugins.async_authentication.AnonymousAuthentication')
# ping/pong interval (unit: second)
PING_INTERVAL = int(os.getenv('PING_INTERVAL', 10))

# #################### Server Config ####################
# As a socks5 server bind host and port
SOCKS5_BIND_HOST = os.getenv('SOCKS5_BIND_HOST', '127.0.0.1')
SOCKS5_BIND_PORT = int(os.getenv('SOCKS5_BIND_PORT', 1080))
# no authentication required
SOCKS5_ALLOW_ANONYMOUS = os.getenv('SOCKS5_ALLOW_ANONYMOUS', 'True').lower() in ['true', 'yes', '1', 't', 'y']
# authentication username and password
SOCKS5_USERNAME = os.getenv('SOCKS5_USERNAME', 'abc')
SOCKS5_PASSWORD = os.getenv('SOCKS5_PASSWORD', '123')

# As an Tunnel server bind host and port
TUNNEL_BIND_HOST = os.getenv('TUNNEL_BIND_HOST', '127.0.0.1')
TUNNEL_BIND_PORT = int(os.getenv('TUNNEL_BIND_PORT', '8888'))

# #################### Agent Config ####################
# the tunnel server host and port
TUNNEL_SERVER_HOST = os.getenv('TUNNEL_SERVER_HOST', '127.0.0.1')
TUNNEL_SERVER_PORT = int(os.getenv('TUNNEL_SERVER_PORT', 8888))
TUNNEL_SERVER_SSL = os.getenv('TUNNEL_SERVER_SSL', 'False').lower() in ['true', 'yes', '1', 't', 'y']

# retry connect tunnel server interval (unit：second)
TUNNEL_SERVER_CONNECT_INTERVAL = int(os.getenv('TUNNEL_SERVER_CONNECT_INTERVAL', 10))
# Reconnect tunnel server times (if less than or equal to 0 retry until successful)
TUNNEL_SERVER_RETRY = int(os.getenv('TUNNEL_SERVER_RETRY', 3))

# #################### Plugin Config ####################
# websocket path
WS_PATH = os.getenv('WS_PATH', '/')
