import aiohttp
import asyncio
from aiohttp import ClientSession, ClientTimeout, TCPConnector, BasicAuth
from loguru import logger
import json
import re


class Twitter:
    def __init__(self):
        self.auth_token = None
        self.proxy_url = None
        self.proxy_auth = None
        self.auth_code = None

        self.ct0 = None

        self.bearer_token = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
        self.default_headers = {
            "authority": "twitter.com",
            "accept": "*/*",
            "accept-language": "en-AU,en;q=0.9",
            "authorization": f"Bearer {self.bearer_token}",
            "cookie": f"guest_id=v1%3A172456496845671342; guest_id_ads=v1%3A172456496845671342; guest_id_marketing=v1%3A172456496845671342; first_ref=https%3A%2F%2Fsidequest.rcade.game%2F; external_referer=padhuUp37ziLv%2B5fSJsAS0PbDT7GT54BWdKU2A9lq%2BM%3D%7C0%7C8e8t2xd8A2w%3D; auth_token={self.auth_token}; kdt=kn4Jx6FaaY24vGUqWXBHp3mz0xfSbPJ2FLJR2Dbw; ct0=974093ff9bd9aea705e175fdb35692a8ded37e8be255761d0c0231baf70c2d8516d819b5f17bbecec29226fc1c1139ef8bce6f0d986c2ab550c2dbc356ccd8ef1b0b43dae96b08b82a9cd13792360925; att=1-S398D2u1a6A65QdcpeghURuboXvY6IdntcQVmqje; twid=u%3D997381730309984256; _monitor_extras={{\"deviceId\":\"kccZSY0fgCOcVvMqvDrA7h\",\"eventId\":2,\"sequenceNumber\":2}}; amp_56bf9d=d61abdfe-ebdf-49f6-bf8c-276fe8fad8a2...1i645du9b.1i6474i35.2.2.4; _twitter_sess=BAh7CSIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoPY3JlYXRlZF9hdGwrCDbBFoiRAToMY3NyZl9p%250AZCIlMDE1ZDRlNzdjOWNkMjhhNWFjNzIxYjAwZDZmYTVkZWU6B2lkIiVmYTE3%250AZWVkOTk1NWE2NDBmY2ZjMzA0MTA3ZTAxYzk4MQ%253D%253D--b3df24067ee9072daf12d4638de0b466fdfda157; lang=en; personalization_id=\"v1_TR9LGOhU0l58o9q9BevfiA==\"",
            "referer": "https://twitter.com/i/oauth2/authorize?client_id=MjBzN0dGSDl5ckJRbmtTSDBNWEY6MTpjaQ&scope=users.read+tweet.read+offline.access+like.read+list.read&response_type=code&redirect_uri=https%3A%2F%2Fsidequest.rcade.game%2F&state=state&code_challenge=challenge&code_challenge_method=plain",
            "sec-ch-ua": "\"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
            "x-client-transaction-id": "kvNyrkxomTPjE/GA8OwUA0MVRoelFglOCH2KV7nSYYVpKeaqhP9q8SZ/JDUIRxncOw9S7pC0vX0yNBZJQ6wAvu/GOKjdkQ",
            "x-client-uuid": "c481463d-1be3-4891-a052-b8bc6171b95f",
            "x-twitter-active-user": "yes",
            "x-csrf-token":"",
            "x-twitter-auth-type": "OAuth2Session",
            "x-twitter-client-language": "en",
            'Cache-Control': 'no-cache'
        }
    

    
    async def process_auth_token_and_proxy(self, client_id, state, code_challenge, auth_token, proxy_url, proxy_auth):
        self.auth_token = auth_token
        self.proxy_url = proxy_url
        self.proxy_auth = proxy_auth

        logger.info(f'使用 auth_token: {self.auth_token}')
        logger.info(f'使用代理: {self.proxy_url}')
        if self.proxy_auth:
            logger.info(f'Proxy Auth: {self.proxy_auth.login} / {self.proxy_auth.password}')
        else:
            logger.info('没有设置代理认证')

        try:
            if await self.twitter_authorize(client_id, state, code_challenge):
                
                logger.info(f'{self.auth_token} 推特授权成功')
            else:
                logger.error(f'{self.auth_token} 推特授权失败')
        except Exception as e:
            logger.error(f'处理授权令牌和代理时发生异常: {e}')


    async def get_auth_code(self, client_id, state, code_challenge):
        try:
            params = {
                'code_challenge': code_challenge,
                'code_challenge_method': 'plain',
                'client_id': client_id,
                'redirect_uri': 'https://sidequest.rcade.game/',
                'response_type': 'code',
                'scope': 'tweet.read users.read follows.read',
                'state': state
            }

            self.bearer_token = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"

            code_defaulf_headers = {
                "authority": "x.com",
                "origin": "https://x.com",
                "x-twitter-active-user": "yes",
                "x-twitter-client-language": "en",
                "authorization": f"Bearer {self.bearer_token}",
                "cookie": f"auth_token={self.auth_token}"
            }

            logger.warning(code_defaulf_headers)

            async with ClientSession(headers=code_defaulf_headers, timeout=ClientTimeout(total=120), connector=TCPConnector(ssl=False)) as session:
                async with session.get('https://twitter.com/i/api/2/oauth2/authorize', params=params, proxy=self.proxy_url, proxy_auth=self.proxy_auth) as response:
                    response_text = await response.text()
                    logger.info(f'Get auth_code response status: {response.status}')
                    logger.debug(f'Get auth_code response text: {response_text}')
                    response_json = await response.json()
                    response_cookies = response.cookies

                    if response.status == 429:
                        logger.warning('Rate limit exceeded. Retrying...')
                        await asyncio.sleep(5)
                        return await self.get_auth_code(client_id, state, code_challenge)

                    if "code" in response_json and response_json["code"] == 353:
                        # 确保正确获取到 `ct0` 的值
                        ct0_cookie = response_cookies.get('ct0')
                        if ct0_cookie:
                            ct0 = ct0_cookie.value
                            logger.info(f"ct0: {ct0}")
                            self.ct0 = ct0
                            # 更新头部
                            code_defaulf_headers["x-csrf-token"] = ct0
                            logger.info('Updated headers: %s', code_defaulf_headers)

                            # 重新发起请求
                            async with session.get('https://twitter.com/i/api/2/oauth2/authorize', params=params, headers=code_defaulf_headers, proxy=self.proxy_url, proxy_auth=self.proxy_auth) as retry_response:
                                retry_response_text = await retry_response.text()
                                logger.info(f'Get auth_code response status after retry: {retry_response.status}')
                                logger.debug(f'Get auth_code response text after retry: {retry_response_text}')
                                if retry_response.status == 200:
                                    retry_response_json = await retry_response.json()
                                    auth_code = retry_response_json['auth_code']
                                    self.auth_code = auth_code
                                    logger.info(f'Auth code{self.auth_code}')
                                    return True
                                else:
                                    logger.error(f'Failed to get auth_code after retry, response content: {retry_response_text}')
                                    return False
                    else:
                        logger.error(f'Failed to get auth_code, response content: {response_text}')
                        return False

        except aiohttp.ClientError as e:
            logger.error(f'Network error during get_auth_code: {e}')
            await asyncio.sleep(5)
            return await self.get_auth_code(client_id, state, code_challenge)
        except Exception as e:
            logger.error(f'Unexpected error during get_auth_code: {e}')
            return False


    async def process_auth_code(self):
        if self.auth_code:
            try:
                # 打开文件并写入 auth_code，文件内容会被覆盖
                with open("auth_codes.txt", "w") as file:
                    file.write(f"{self.auth_code}\n")
                logger.info(f'auth_code {self.auth_code} 已成功保存到文件。')
            except Exception as e:
                logger.error(f'保存 auth_code 时出错：{e}')


    async def twitter_authorize(self, client_id, state, code_challenge):
        if not await self.get_auth_code(client_id, state, code_challenge) and self.auth_token:
            logger.error(f'{self.auth_token}')
            logger.error('Failed to get auth code')
            return False

        data = {
            'approval': 'true',
            'code': self.auth_code,
        }

        self.default_headers.update({"cookie": f"guest_id=v1%3A172456496845671342; guest_id_ads=v1%3A172456496845671342; guest_id_marketing=v1%3A172456496845671342; first_ref=https%3A%2F%2Fsidequest.rcade.game%2F; external_referer=padhuUp37ziLv%2B5fSJsAS0PbDT7GT54BWdKU2A9lq%2BM%3D%7C0%7C8e8t2xd8A2w%3D; auth_token={self.auth_token}; kdt=kn4Jx6FaaY24vGUqWXBHp3mz0xfSbPJ2FLJR2Dbw; ct0={self.ct0}; att=1-S398D2u1a6A65QdcpeghURuboXvY6IdntcQVmqje; twid=u%3D997381730309984256; _monitor_extras={{\"deviceId\":\"kccZSY0fgCOcVvMqvDrA7h\",\"eventId\":2,\"sequenceNumber\":2}}; amp_56bf9d=d61abdfe-ebdf-49f6-bf8c-276fe8fad8a2...1i645du9b.1i6474i35.2.2.4; _twitter_sess=BAh7CSIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoPY3JlYXRlZF9hdGwrCDbBFoiRAToMY3NyZl9p%250AZCIlMDE1ZDRlNzdjOWNkMjhhNWFjNzIxYjAwZDZmYTVkZWU6B2lkIiVmYTE3%250AZWVkOTk1NWE2NDBmY2ZjMzA0MTA3ZTAxYzk4MQ%253D%253D--b3df24067ee9072daf12d4638de0b466fdfda157; lang=en; personalization_id=\"v1_TR9LGOhU0l58o9q9BevfiA==\""})
        self.default_headers.update({"x-csrf-token": self.ct0})
        data.update({'code': self.auth_code})
        logger.info(f'Authorization code {self.default_headers} {self.ct0} {data}')

        try:
            connector = TCPConnector(ssl=False)
            async with ClientSession(headers=self.default_headers, timeout=ClientTimeout(total=120), connector=connector) as session:
                async with session.post('https://twitter.com/i/api/2/oauth2/authorize', data=data, proxy=self.proxy_url, proxy_auth=self.proxy_auth) as response:
                    response_text = await response.text()
                    logger.info(f'Twitter authorize response status: {response.status}')
                    logger.debug(f'Twitter authorize response text: {response_text}')

                    if response.status == 200 and 'redirect_uri' in response_text:
                        await self.process_auth_code()  # 确保调用保存 auth_code 的方法
                        return True
                    elif response.status == 429:
                        logger.warning('Rate limit exceeded. Retrying...')
                        await asyncio.sleep(5)
                        return await self.twitter_authorize(client_id, state, code_challenge)
                    elif response.status == 401:
                        logger.error('Authentication failed. Check your auth token and credentials.')
                    else:
                        logger.error(f'Twitter authorization failed, response content: {response_text}')
                    return False
        except aiohttp.ClientError as e:
            logger.error(f'Twitter authorization network error: {e}')
            return False
        except Exception as e:
            logger.error(f'Unexpected error during Twitter authorization: {e}')
            return False




async def get_proxies():
    try:
        with open("proxy.txt", 'r') as file:
            proxies = []
            for line in file:
                parts = line.strip().split(':')
                if len(parts) == 4:
                    ip, port, username, password = parts
                    proxy_url = f'http://{ip}:{port}'
                    proxy_auth = BasicAuth(login=username, password=password)
                    proxies.append((proxy_url, proxy_auth))
                else:
                    logger.warning(f"代理文件格式不正确: {line.strip()}")
            return proxies
    except FileNotFoundError:
        logger.error('proxy.txt 文件未找到，请检查路径')
    except Exception as e:
        logger.error(f'读取代理文件出错: {e}')
    return []

async def get_auth_tokens():
    try:
        with open("auth_token.txt", 'r') as file:
            tokens = [line.strip() for line in file if line.strip()]
            return tokens
    except FileNotFoundError:
        logger.error('auth_token.txt 文件未找到，请检查路径')
    except Exception as e:
        logger.error(f'读取 auth_token 文件出错: {e}')
    return []

async def main():
    client_id = 'MjBzN0dGSDl5ckJRbmtTSDBNWEY6MTpjaQ'
    state = 'state'
    code_challenge = 'challenge'
    
    twitter = Twitter()
    proxies = await get_proxies()
    auth_tokens = await get_auth_tokens()

    if not proxies or not auth_tokens:
        logger.info("没有更多的授权令牌或代理可用")
        return

    for auth_token in auth_tokens:
        for proxy_url, proxy_auth in proxies:
            logger.info(f"正在使用 auth_token: {auth_token} 和代理: {proxy_url}")
            await twitter.process_auth_token_and_proxy(client_id, state, code_challenge, auth_token, proxy_url, proxy_auth)
            proxies.remove((proxy_url, proxy_auth))  # 移除使用过的代理
            break  # 处理完一个 auth_token 后，跳出代理循环

    logger.info("所有账户处理完毕，执行其他操作...")
    
asyncio.run(main())
