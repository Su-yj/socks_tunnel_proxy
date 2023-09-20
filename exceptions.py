class UnknownTypeException(Exception):
    """未知的类型"""


class UnknownSystemException(Exception):
    """未知类型的系统"""


class UnknownCMDException(Exception):
    """未知的 CMD 类型"""


class AuthenticationFailedException(Exception):
    """服务端认证失败"""


class PingPongTimeOutException(Exception):
    """ping/pong 超时"""
