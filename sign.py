from eth_account import Account
from eth_account.messages import encode_defunct

class eth_util:
    def __init__(self):
        return
    def sign(private_key) :
            # 你的以太坊私钥
        private_key = private_key

        # 创建Account对象
        account = Account.from_key(private_key)

        # 要签名的消息
        message = "Welcome to Side Quests!\n\nClick to sign in and accept the Side Quests and Revolvinggames Terms of Service and Privacy Policy.\n\nThis request will not trigger a blockchain transaction or cost any gas fees."

        # 将消息编码成适合签名的格式
        message_encoded = encode_defunct(text=message)

        # 生成签名
        signed_message = account.sign_message(message_encoded)
        signature = signed_message.signature
        hexSignature  =  signature.hex()
        print(f"签名: {signature.hex()}")
        return hexSignature
        
    def create_wallet(self,name):
        # 创建新的以太坊钱包
        account = Account.create()
        private_key = account.privateKey.hex()
        public_key = account.address
        
        # 保存私钥和公钥到文件
        with open('wallet.txt', 'w') as file:
            file.write(f"{private_key}+推特名字：{name}")
        
        return private_key
    
    if __name__ == "__main__":
        # 这个代码块只有在直接运行 sign.py 时才会执行
        print("sign.py is being run directly")
        sign()
        create_wallet()