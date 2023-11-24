# #################### Public Config ####################
# packet forwarding size（1024~4096）
BUFFER_SIZE = 1024
# log level (DEBUG | INFO | WARNING | ERROR | CRITICAL)
LOG_LEVEL = 'DEBUG'
# backends
# CONNECTION_BACKEND = 'plugins.async_connection.SocketConnection'
CONNECTION_BACKEND = 'plugins.async_ws_connection.WebSocketConnection'
# CONNECTION_BACKEND = 'plugins.connection.SocketConnection'
AUTHENTICATION_BACKEND = 'plugins.async_authentication.AnonymousAuthentication'
# AUTHENTICATION_BACKEND = 'plugins.authentication.AnonymousAuthentication'
# ping/pong interval (unit: second)
PING_INTERVAL = 10

# #################### Server Config ####################
# As a socks5 server bind host and port
SOCKS5_BIND_HOST = '0.0.0.0'
SOCKS5_BIND_PORT = 8888
# no authentication required
SOCKS5_ALLOW_ANONYMOUS = True
# authentication username and password
SOCKS5_USERNAME = 'abc'
SOCKS5_PASSWORD = '123'

# As an Tunnel server bind host and port
TUNNEL_BIND_HOST = '0.0.0.0'
TUNNEL_BIND_PORT = 8889

# #################### Agent Config ####################
# the tunnel server host and port
TUNNEL_SERVER_HOST = 'localhost'
# TUNNEL_SERVER_HOST = '192.168.179.132'
TUNNEL_SERVER_PORT = 8889

# retry connect tunnel server interval (unit：second)
TUNNEL_SERVER_CONNECT_INTERVAL = 1
# Reconnect tunnel server times (if less than or equal to 0 retry until successful)
TUNNEL_SERVER_RETRY = 0
