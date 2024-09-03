
import aiohttp
import asyncio
from aiohttp import ClientSession, ClientTimeout, TCPConnector, BasicAuth
from datetime import datetime
import random
from loguru import logger
import json
import sign

class Rcade:
    def __init__(self):
        self.default_headers = {
            "authority": "lb.backend-sidequest.rcade.game",
            "accept": "*/*",
            "accept-language": "en-AU,en;q=0.9",
            "content-type": "text/plain;charset=UTF-8",
            "origin": "https://sidequest.rcade.game",
            "referer": "https://sidequest.rcade.game/",
            "sec-ch-ua": "\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
        }
        self.tw_name = ""
        self.au_token = ""
        self.proxy_url = None  # Default to no proxy
        self.proxy_auth = None

    def set_proxy(self, proxy_url, proxy_auth):
        self.proxy_url = proxy_url
        self.proxy_auth = proxy_auth

    def set_auth_token(self, auth_token):
        self.au_token = auth_token
    
    
    # 现有的初始化和其他方法...

    async def process_auth_token_and_proxy(self, client_id, state, code_challenge, auth_token, proxy_url=None, proxy_auth=None):
            # 设置 auth_token 和代理
            self.set_auth_token(auth_token)
            self.set_proxy(proxy_url, proxy_auth)
            
            # 假设在这里你需要用 auth_token 进行登录或其他操作
            # 例如，你可以调用 rcade_login 方法进行登录
            auth_codes = await self.read_auth_codes_from_file("auth_codes.txt")
            if not auth_codes:
                logger.info("没有更多的 auth_code 可用")
                return

            for auth_code in auth_codes:
                logger.info(f"正在使用 auth_code: {auth_code} 和代理: {proxy_url}")
                await self.rcade_login(auth_code, proxy_url, proxy_auth)


    async def read_auth_codes_from_file(self, file_path="auth_codes.txt"):
        auth_codes = []
        try:
            with open(file_path, "r") as file:
                auth_codes = [line.strip() for line in file.readlines()]
        except FileNotFoundError:
            logger.error(f"文件 {file_path} 未找到。")
        except Exception as e:
            logger.error(f"读取文件时出错：{e}")
        return auth_codes

    async def process_auth_codes(self, file_path="auth_codes.txt", proxy_url=None, proxy_auth=None):
        auth_codes = await self.read_auth_codes_from_file(file_path)
        if not auth_codes:
            print("没有更多的 auth_code 可用")
            return

        for auth_code in auth_codes:
            print(f"正在使用 auth_code: {auth_code} 和代理: {proxy_url}")
            await self.rcade_login(auth_code, proxy_url, proxy_auth)

    async def rcade_login(self, auth_code, proxy_url=None, proxy_auth=None):
        url = "https://lb.backend-sidequest.rcade.game/users/login"
        data = f'{{"code":"{auth_code}"}}'
        logger.info(f'rcade_login 请求数据: {data}')
        
        kwargs = {}
        if proxy_url:
            kwargs['proxy'] = proxy_url
        if proxy_auth:
            kwargs['proxy_auth'] = proxy_auth

        connector = TCPConnector(limit_per_host=0, keepalive_timeout=0)  # 禁用连接池
        
        async with ClientSession(headers=self.default_headers, timeout=ClientTimeout(total=120), connector=connector) as session:
            try:
                async with session.post(url, data=data, **kwargs) as response:
                    response_text = await response.text()
                    try:
                        response_json = await response.json()
                    except Exception as e:
                        response_json = {}
                        logger.error(f'解析响应 JSON 时出错：{e}')
                    
                    logger.info(f'rcade_login 响应状态: {response.status}')
                    print(auth_code, '--------------------------')
                    
                    if response.status == 200:
                        user = response_json.get('user', {})
                        points = user.get('points', '无积分信息')
                        userid = user.get('_id', 'XXXXXXXX')
                        logger.info(f'积分: {points}')
                        logger.info(f'用户 ID: {userid}')
                        self.set_auth_token(user.get('authToken', "无token"))
                        logger.info(f'用户token: {self.au_token}')
                        quests = response_json.get('availableQuests', [])
                        current_time = datetime.now()

                         # 处理任务
                        await self.process_quests(user, quests, current_time)


                        # wallets = user.get('wallets')
                        # self.tw_name = user.get('referror')
                        # for quest in quests:
                        #     logger.info(f'当前 auth_token: {self.au_token}')
                        #     logger.info(f'当前用户 ID: {userid}')

                        #     if quest.get('title') == 'Link Wallet' and not(wallets) :
                        #         await asyncio.sleep(pause_time)
                        #         await self.Binding_wallet(user_id=userid,quest_id=2)
                        #         return
                        #     else:
                        #         for complete_quest, timestamp in user.get('quests', {}).items():
                        #             if complete_quest == quest.get('_id'):
                        #                 logger.info(f'任务全部完成,{userid}')
                        #                 return
                        #             elif complete_quest == 1:
                        #                 completed_time = datetime.fromtimestamp(timestamp)
                        #                 if current_time > completed_time:
                        #                     logger.info(f'签到任务已经完成,{userid}')  
                        #             else:
                        #                 pause_time = random.uniform(20, 40)
                        #                 logger.info(f'Pausing for {pause_time:.2f} seconds...')
                        #                 await asyncio.sleep(pause_time)
                        #                 await self.fetch_quest_info(user_id=user.get('_id'), quest_id=quest.get('_id'))
                        
                        return response_json
                    elif response.status == 400:
                        logger.error(f'请求失败，状态码: {response.status}, 原因: {response_json.get("details", "无详细信息")}')
                        return None
                    elif response.status == 429:
                        logger.warning('请求过于频繁，稍后重试...')
                        await asyncio.sleep(5)
                        return await self.rcade_login(auth_code, proxy_url, proxy_auth)
                    else:
                        logger.error(f'rcade_login 失败，状态码: {response.status}')
                        return None
            except aiohttp.ClientError as e:
                logger.error(f'rcade_login 时网络错误：{e}')
                await asyncio.sleep(5)  # Retry after waiting
                return await self.rcade_login(auth_code, proxy_url, proxy_auth)
            except Exception as e:
                logger.error(f'rcade_login 异常：{e}')
                return None

    async def process_quests(self, user, quests, current_time):
        # 获取用户已完成的任务
        completed_quests = user.get('quests', {})

        # 标记是否需要绑定钱包
        needs_wallet_binding = False

        # 遍历所有任务
        for quest in quests:
            quest_id = quest.get('_id')
            quest_title = quest.get('title')

            logger.info(f'当前 auth_token: {self.au_token}')
            logger.info(f'当前用户 ID: {user.get("_id")}')
            
            if quest_title == 'Link Wallet' and not user.get('wallets'):
                # 如果任务是绑定钱包且用户未绑定钱包
                logger.info(f'用户 {user.get("_id")} 需要绑定钱包')
                needs_wallet_binding = True
                # 暂停一段时间然后绑定钱包
                await asyncio.sleep(random.uniform(20, 40))
                await self.Binding_wallet(user_id=user.get('_id'), quest_id=quest_id)
                return  # 绑定钱包后退出，不继续处理其他任务

        # 如果没有需要绑定钱包的任务，则检查其他任务
        if not needs_wallet_binding:
            for quest in quests:
                quest_id = quest.get('_id')

                if quest_id in completed_quests:
                    logger.info(f'任务 {quest_id} 已完成,{user.get("_id")}')
                    continue  # 跳过已完成的任务
                else:
                    # 任务未完成，暂停并重新请求任务信息
                    pause_time = random.uniform(20, 40)
                    logger.info(f'任务 {quest_id} 未完成, Pausing for {pause_time:.2f} seconds...')
                    await asyncio.sleep(pause_time)
                    await self.fetch_quest_info(user_id=user.get('_id'), quest_id=quest_id)




    async def process_quests(self, user, quests, current_time):
        all_quests_completed = True
        
        for quest in quests:
            quest_id = quest.get('_id')
            quest_title = quest.get('title')
            if quest_id in user.get('quests', {}):
                # 任务已经完成
                logger.info(f'任务 {quest_title} 已完成,{user.get("_id")}')
            else:
                # 任务未完成
                all_quests_completed = False
                # 进行任务相关处理
                pause_time = random.uniform(20, 40)
                logger.info(f'Pausing for {pause_time:.2f} seconds...')
                await asyncio.sleep(pause_time)
                await self.fetch_quest_info(user_id=user.get('_id'), quest_id=quest_id)
        
        if all_quests_completed:
            logger.info(f'所有任务完成,{user.get("_id")}')
        else:
            logger.info(f'部分任务未完成,{user.get("_id")}')


    async def fetch_quest_info(self, user_id, quest_id):
        url = f"https://lb.backend-sidequest.rcade.game/users/{user_id}/quests/{quest_id}"
        data = "{}"
        headers = { 
            'Authorization': f"Bearer {self.au_token}",
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Content-Type': 'text/plain;charset=UTF-8',
            'Origin': 'https://sidequest.rcade.game',
            'Referer': 'https://sidequest.rcade.game/',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36'
        }

        logger.info(f'Fetching quest info from URL: {url}')
        logger.info(f'Request headers: {headers}')
        logger.info(f'Request data: {data}')
        
        connector = TCPConnector(limit_per_host=0, keepalive_timeout=0)  # Disable connection pool

        async with ClientSession(headers=headers, timeout=ClientTimeout(total=120), connector=connector) as session:
            try:
                async with session.post(url, data=data, proxy=self.proxy_url, proxy_auth=self.proxy_auth) as response:
                    response_text = await response.text()
                    try:
                        response_json = await response.json()
                    except aiohttp.ContentTypeError:
                        response_json = {}

                    logger.info(f'Quest info response status: {response.status}')
                    logger.info(f'Quest info response text: {response_text}')

                    if response.status == 200:
                        await self.fetch_user_info(user_id=user_id)
                        return response_json
                    elif response.status == 429:
                        logger.warning('请求过于频繁，稍后重试...')
                        await asyncio.sleep(5)
                        return await self.fetch_quest_info(user_id, quest_id)
                    elif response.status in [401, 403]:  # Unauthorized or Forbidden
                        logger.error(f'需要重新认证，状态码: {response.status}')
                        await self.rcade_login()  # 重新登录
                        return await self.fetch_quest_info(user_id, quest_id)  # 重试请求
                    elif response.status == 400:
                        logger.error(f'请求失败，状态码: {response.status}, 原因: {response_json.get("details", "无详细信息")}')
                        # 处理400错误的具体逻辑，例如检查请求数据是否有误
                        return None
                    else:
                        logger.error(f'获取任务信息失败，状态码: {response.status}')
                        return None
            except aiohttp.ClientError as e:
                logger.error(f'网络错误：{e}')
                await asyncio.sleep(5)  # Retry after waiting
                return await self.fetch_quest_info(user_id, quest_id)
            except Exception as e:
                logger.error(f'异常：{e}')
                return None

            
    async def fetch_user_info(self, user_id):
        url = f"https://lb.backend-sidequest.rcade.game/users/{user_id}"
        headers = {
            **self.default_headers,
            "authorization": f"Bearer {self.au_token}"
        }
        logger.info(f'fetch_user_info 请求URL: {url}, 代理: {self.proxy_url}, 代理认证: {self.proxy_auth}')

        connector = TCPConnector()

        async with ClientSession(timeout=ClientTimeout(total=120), connector=connector) as session:
            try:
                async with session.get(
                    url,
                    headers=headers,
                    proxy=self.proxy_url,
                    proxy_auth=self.proxy_auth
                ) as response:
                    response_text = await response.text()
                    response_json = {}
                    try:
                        response_json = await response.json()
                    except ValueError:
                        pass

                    # logger.info(f'fetch_user_info 响应状态: {response.status}, 响应内容: {response_text}')
                    
                    if response.status == 200:
                        user = response_json.get('user', {})
                        points = user.get('points', '无积分')
                        walletAddress = user.get('walletAddress', '没绑定钱包')
                        logger.info(f'积分：{points}, 钱包：{walletAddress}')
                        return response_json
                    else:
                        logger.error(f'fetch_user_info 错误，状态码: {response.status}')
                        return None
            except aiohttp.ClientError as e:
                logger.error(f'网络错误：{e}')
                return None
            except Exception as e:
                logger.error(f'异常：{e}')
                return None
            
    async def Binding_wallet(self, user_id, quest_id, data):
        url = f"https://lb.backend-sidequest.rcade.game/users/{user_id}/quests/{quest_id}"
        headers = {
            **self.default_headers,
            "authorization": f"Bearer {self.auth_token}"
        }
        private_key = sign.create_wallet(name=self.tw_name)
        data = sign.eth_util.sign(private_key=private_key)
        body = json.dumps(data)

        logger.info(f'请求 URL: {url}')
        logger.info(f'请求头: {headers}')
        logger.info(f'请求数据: {body}')

        connector = TCPConnector(limit_per_host=0, keepalive_timeout=0)  # 禁用连接池
        
        async with ClientSession(headers=headers, timeout=ClientTimeout(total=120), connector=connector) as session:
            try:
                async with session.post(url, data=body, proxy=self.proxy_url, proxy_auth=self.proxy_auth) as response:
                    response_text = await response.text()
                    try:
                        response_json = await response.json()
                    except aiohttp.ContentTypeError:
                        response_json = {}

                    logger.info(f'响应状态: {response.status}')
                    logger.info(f'响应内容: {response_text}')
                    
                    if response.status == 200:
                        logger.info('绑定钱包成功')
                        return response_json
                    elif response.status == 400:
                        logger.error(f'请求失败，状态码: {response.status}, 原因: {response_json.get("details", "无详细信息")}')
                        return None
                    elif response.status == 429:
                        logger.warning('请求过于频繁，稍后重试...')
                        await asyncio.sleep(5)
                        return await self.post_quest_data(user_id, quest_id, data)
                    else:
                        logger.error(f'请求失败，状态码: {response.status}')
                        return None
            except aiohttp.ClientError as e:
                logger.error(f'网络错误：{e}')
                await asyncio.sleep(5)  # Retry after waiting
                return await self.post_quest_data(user_id, quest_id, data)
            except Exception as e:
                    logger.error(f'异常：{e}')
                    return None


async def get_proxies():
    try:
        with open("proxy.txt", 'r') as file:
            lines = file.readlines()
            proxies = []
            for line in lines:
                parts = line.strip().split(':')
                if len(parts) == 4:
                    ip, port, username, password = parts
                    proxy_url = f'http://{ip}:{port}'
                    proxy_auth = BasicAuth(login=username, password=password)
                    proxies.append((proxy_url, proxy_auth))
                else:
                    print(f"代理文件格式不正确: {line.strip()}")
            return proxies
    except FileNotFoundError:
        print('proxy.txt 文件未找到，请检查路径')
    except Exception as e:
        print(f'读取代理文件出错: {e}')
    return []

async def get_auth_tokens():
    try:
        with open("auth_codes.txt", 'r') as file:
            lines = file.readlines()
            tokens = [line.strip() for line in lines if line.strip()]
            return tokens
    except FileNotFoundError:
        print('auth_codes.txt 文件未找到，请检查路径')
    except Exception as e:
        print(f'读取 auth_token 文件出错: {e}')
    return []

async def main():
    client_id = 'MjBzN0dGSDl5ckJRbmtTSDBNWEY6MTpjaQ'
    state = 'state'
    code_challenge = 'challenge'
    
    rcade = Rcade()
    proxies = await get_proxies()
    auth_tokens = await get_auth_tokens()

    if not proxies or not auth_tokens:
        print("没有更多的授权令牌或代理可用")
        return

    for auth_token in auth_tokens:
        for proxy_url, proxy_auth in proxies:
            print(f"正在使用 auth_token: {auth_token} 和代理: {proxy_url}")
            await rcade.process_auth_token_and_proxy(client_id, state, code_challenge, auth_token, proxy_url, proxy_auth)
            proxies.remove((proxy_url, proxy_auth))  # 移除使用过的代理
            break  # 处理完一个 auth_token 后，跳出代理循环

    # 执行其他操作，例如通知系统或进行其他任务
    logger.info("所有账户处理完毕，执行其他操作...")
    # 根据实际需求执行其他操作

asyncio.run(main())
