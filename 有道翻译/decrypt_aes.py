
import base64
import hashlib
from Crypto.Cipher import AES

def result(text_AES):
    #   偏移量
    decodeiv = "ydsecret://query/iv/C@lZe2YzHtZ2CYgaXKSVfsb7Y4QWHjITPPZ0nQp87fBeJ!Iv6v^6fvi2WN@bYpJ4"
    # 秘钥
    decodekey = "ydsecret://query/key/B*RGygVywfNBwpmBaZg*WT7SIOUP2T0C9WHMZN39j^DAdaZhAnxvGcCY6VYFwnHl"
    # 先把密匙和偏移量进行md5加密 digest()是返回二进制的值
    key = hashlib.md5(decodekey.encode(encoding='utf-8')).digest()
    iv = hashlib.md5(decodeiv.encode(encoding='utf-8')).digest()
    # AES解密 CBC模式解密
    aes_en = AES.new(key, AES.MODE_CBC, iv)
    # 将已经加密的数据放进该方法
    data_new = base64.urlsafe_b64decode(text_AES)
    # 参数准备完毕后，进行解密
    result = aes_en.decrypt(data_new).decode('utf-8')
    return result

# 示例数据
ciphertext = 'Z21kD9ZK1ke6ugku2ccWuwRmpItPkRr5XcmzOgAKD0GcaHTZL9kyNKkN2aYY6yiOj9hqLPCsBaHYuaKLEhgClrpuT4Xidksvq5ZLQrSodK9eJnobSBP_tOlHbfwM7N86xDyHVTwdNapEtDM412nhRQgCB1K2zOg2Cd2ggE2OCS4='




# 解密
plaintext = result(ciphertext)
print("解密后的数据:", plaintext)
