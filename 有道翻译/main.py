from datetime import datetime
import asyncio
import httpx
import base64
import hashlib
import re
from Crypto.Cipher import AES


class Yd_translate(object):
    def __init__(self, *, input, mode_from='zh-CHS', mode_to='en'):
        self.input = input
        self.output = None
        self.mode_from = mode_from
        self.mode_to = mode_to
        self.cookies = {
            'OUTFOX_SEARCH_USER_ID': '1480905637@10.55.164.97',
            'OUTFOX_SEARCH_USER_ID_NCOO': '97415245.13830516',
        }
        self.headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9,ga;q=0.8',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            # 'Cookie': 'OUTFOX_SEARCH_USER_ID=1480905637@10.55.164.97; OUTFOX_SEARCH_USER_ID_NCOO=97415245.13830516',
            'Origin': 'https://fanyi.youdao.com',
            'Referer': 'https://fanyi.youdao.com/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
        }

    @staticmethod
    def get_sign():
        u = "fanyideskweb"
        d = "webfanyi"
        e = int(datetime.now().timestamp() * 1000)
        t = 'fsdsogkndfokasodnaso'
        m_md5 = hashlib.md5()
        m_md5.update(f'client={u}&mysticTime={e}&product={d}&key={t}'.encode('utf8'))
        sign = m_md5.hexdigest()
        return sign, e

    def process_xpath(self):
        if self.output:
            pattern = r'{"tgt":(.*),"src":'
            temp_con = re.findall(pattern, self.output)[0]
            self.output = temp_con
        else:
            print('为进行请求')

    async def make_request(self):
        self.sign, self.time = self.get_sign()

        self.data = {
            'i': self.input,
            'from': self.mode_from,
            'to': self.mode_to,
            'domain': '0',
            'dictResult': 'true',
            'keyid': 'webfanyi',
            'sign': self.sign,
            'client': 'fanyideskweb',
            'product': 'webfanyi',
            'appVersion': '1.0.0',
            'vendor': 'web',
            'pointParam': 'client,mysticTime,product',
            'mysticTime': self.time,
            'keyfrom': 'fanyi.web',
            'mid': '1',
            'screen': '1',
            'model': '1',
            'network': 'wifi',
            'abtest': '0',
            'yduuid': 'abcdefg', }

        async with httpx.AsyncClient() as client:
            resp = await client.post(url='https://dict.youdao.com/webtranslate', cookies=self.cookies,
                                     headers=self.headers, data=self.data)
            print('未解密的数据为：', resp.text)
            self.output = await self.decrypt(resp.text)
            self.process_xpath()
            print('解密后的数据为：', self.output)

    async def decrypt(self, text_AES):
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


if __name__ == '__main__':
    ddl = Yd_translate(input='狗')
    asyncio.run(ddl.make_request())
