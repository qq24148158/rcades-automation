# 项目概述

本项目包含两个主要脚本，用于处理 Rcade 用户的登录、任务管理和以太坊钱包生成及签名。

## 脚本说明

### `rcade.py`

用于处理 Rcade 用户的登录、任务处理等操作。主要功能包括：
- 从文件中读取授权令牌和代理
- 使用授权令牌登录
- 获取用户任务并处理这些任务
- 处理钱包绑定操作

### `sign.py`

用于生成以太坊钱包和签名消息。主要功能包括：
- 使用以太坊私钥对消息进行签名
- 创建新的以太坊钱包并保存私钥和公钥

## 安装依赖

您需要安装以下 Python 包：
- `aiohttp`：用于异步 HTTP 请求
- `loguru`：用于日志记录
- `eth-account`：用于以太坊账户和消息处理

可以通过以下命令安装这些包：

```bash
pip install aiohttp loguru eth-account
