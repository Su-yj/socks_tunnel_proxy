## Agent 连接过程
### 1. Agent 向服务器发起连接
Agent 向服务器发起 Http 请求（具体认证数据可根据实际修改）
### 2. 服务器响应

| RESULT |
| :---: |
| 1 |

* RESULT: 认证结果。成功：0x00；失败：0xFF

## 代理请求过程
### 1. 创建新的连接

服务端数据：

| TYPE | ID.LEN | ID | CMD | ATYP | DST.ADDR | DST.PORT |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 1 | Variable | 1 | 1 | Variable | 2 |

* TYPE: 请求类型，这里的值是 0x01
* ID.LEN: 标识ID的长度
* ID: 标识ID
* CMD: SOCK的命令码：
    * CONNECT 0x01
    * BIND 0x02
    * UDP ASSOCIATE 0x03
* ATYP: 地址类型：
    * IPV4 address: 0x01
    * DOMAIN NAME: 0x03
    * IPV6 address: 0x04
* DST.ADDR: 目的地址
* DST.PORT: 目的端口


客户端响应：

| TYPE | ID.LEN | ID | REP | ATYP | BND.ADDR | BND.PORT |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | 1 | Variable | 1 | 1 | Variable | 2 |

* TYPE: 请求类型，这里返回的是 0x01
* ID.LEN: 标识ID的长度
* ID: 标识ID
* REP: 应答状态码：
    * 0x00  succeeded
    * 0x01  general socks server failure
    * 0x02  connection not allowed by ruleset
    * 0x03  Network unreachable
    * 0x04  Host unreachable
    * 0x05  Connection refused
    * 0x06  TTL expired
    * 0x07  Command not supported
    * 0x08  Address type not supported
    * 0x09~0xFF  unassigned
* ATYP: 地址类型：
    * IPV4 address: 0x01
    * DOMAIN NAME: 0x03
    * IPV6 address: 0x04
* BND.ADDR: agent 绑定的地址
* BND.PORT: agent 绑定的端口DST.PORT

### 2. 数据发送阶段

服务端数据：

| TYPE | ID.LEN | ID | LEN | DATA |
| :---: | :---: | :---: | :---: | :---: |
| 1 | 1 | Variable | 2 | Variable |

* TYPE: 请求类型，这里是 0x02
* ID.LEN: 标识ID的长度
* ID: 标识ID
* LEN: 数据长度
* DATA: 需要发送的数据，最大4096

客户端响应：

| TYPE | ID.LEN | ID | LEN | DATA |
| :---: | :---: | :---: | :---: | :---: |
| 1 | 1 | Variable | 2 | Variable |

* TYPE: 请求类型，这里是 0x02
* ID.LEN: 标识ID的长度
* ID: 标识ID
* LEN: 数据长度
* DATA: 需要发送的数据，最大4096

### 3. 服务端请求 agent 断开绑定的连接

服务端数据：

| TYPE | ID.LEN | ID |
| :---: | :---: | :---: |
| 1 | 1 | Variable |

* TYPE: 请求类型，这里是 0x03
* ID.LEN: 标识ID的长度
* ID: 标识ID

客户端响应（应该不用响应了）：

| TYPE | RSV |
| :---: | :---: |
| 1 | 1 |

* TYPE: 请求类型，这里是 0x03
* RSV: 保留字段，一般为 0x00

### 4. agent 连接断开后向服务端发送的数据

客户端数据：

| TYPE | ID.LEN | ID |
| :---: | :---: | :---: |
| 1 | 1 | Variable |

* TYPE: 请求类型，这里是 0x04
* ID.LEN: 标识ID的长度
* ID: 标识ID

服务端响应（不用响应了）：

| TYPE | RSV |
| :---: | :---: |
| 1 | 1 |

* TYPE: 请求类型，这里是 0x04
* RSV: 保留字段，一般为 0x00

### 5. Ping

服务端/客户端：
> 服务端/客户端应响应 Pong

| TYPE |
| :---: |
| 1 |

* TYPE: 请求类型，这里是 0x05

### 6. Pong

服务端/客户端：
> 服务端/客户端不需要响应

| TYPE |
| :---: |
| 1 |

* TYPE: 请求类型，这里是 0x06
