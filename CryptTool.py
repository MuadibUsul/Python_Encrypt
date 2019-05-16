# -*- coding：utf-8 -*-
import base64
import rsa
from Crypto.Cipher import AES
import hashlib
import time


class USE_AES:
    """
    AES
    除了MODE_SIV模式key长度为：32, 48, or 64,
    其余key长度为16, 24 or 32
    详细见AES内部文档
    CBC模式传入iv参数
    本例使用常用的ECB模式
    """

    def __init__(self, key):
        if len(key) > 32:
            key = key[:32]
        self.key = self.to_16(key)

    def to_16(self, key):
        """
        转为16倍数的bytes数据
        :param key:
        :return:
        """
        key = bytes(key, encoding="utf8")
        while len(key) % 16 != 0:
            key += b'\0'
        return key  # 返回bytes

    def aes(self):
        return AES.new(self.key, AES.MODE_ECB)  # 初始化加密器

    def AES_ECRYPT(self, text):
        aes = self.aes()
        return str(base64.encodebytes(aes.encrypt(self.to_16(text))),
                   encoding='utf8').replace('\n', '')  # 加密

    def AES_DECRYPT(self, text):
        aes = self.aes()
        return str(aes.decrypt(base64.decodebytes(bytes(
            text, encoding='utf8'))).rstrip(b'\0').decode("utf8"))  # 解密


class USE_RSA:
    """
    生成密钥可保存.pem格式文件
    1024位的证书，加密时最大支持117个字节，解密时为128；
    2048位的证书，加密时最大支持245个字节，解密时为256。
    加密大文件时需要先用AES或者DES加密，再用RSA加密密钥，详细见文档
    文档:https://stuvel.eu/files/python-rsa-doc/usage.html#generating-keys
    """

    def __init__(self, prav, pub):
        """
        :param number: 公钥、私钥
        """
        with open(prav, "rb") as x:
            e = x.read()
            self.privkey = rsa.PrivateKey.load_pkcs1(e)  # load 私钥
        with open(pub, "rb") as x:
            f = x.read()
            self.pubkey = rsa.PublicKey.load_pkcs1(f)  # load 公钥，由于之前生成的私钥缺少'RSA'字段，故无法 load
        # self.pubkey, self.privkey = rsa.newkeys(number)

    def RSA_ENCRYPT(self, message, num):
        """
        :param message:
        :return: bytes
        """
        content = message.encode('utf-8')
        if num == 1:
            # num = 1时， 用公钥加密
            crypto = rsa.encrypt(content, self.pubkey)
        elif num == 0:
            # num = 0时， 用私钥加密
            crypto = rsa.encrypt(content, self.privkey)
        return crypto

    def RSA_DECRYPT(self, message, num):
        """
        :param num:
        :param message:
        :return: str
        """
        if num == 1:
            # num=1 时候， 用私钥解密
            content = rsa.decrypt(message, self.privkey)
        elif num == 0:
            # num=0 时候， 用公钥解密
            content = rsa.decrypt(message, self.pubkey)
        con = content.decode('utf-8')
        return con

    def savePem(self, path_name, text):
        """
        :param path_name: 保存路径
        :param text: str
        :return:bytes
        """
        if "PEM" in path_name.upper():
            path_name = path_name[:-4]
        with open('{}.pem'.format(path_name), 'bw') as f:
            f.write(text.save_pkcs1())

    def readPem(self, path_name, key_type):
        """
        :param path_name: 密钥文件
        :param key_type:类型 
        :return: 
        """
        if 'pubkey' in key_type:
            self.pubkey = rsa.PublicKey.load_pkcs1(path_name)
        else:
            self.privkey = rsa.PublicKey.load_pkcs1(path_name)
        return True

    def sign(self, message, priv_key=None, hash_method='MD5'):
        """
        生成明文的哈希签名以便还原后对照
        :param message: str
        :param priv_key:
        :param hash_method: 哈希的模式
        :return:
        """
        if None == priv_key:
            priv_key = self.privkey
        return rsa.sign(message.encode(), priv_key, hash_method)

    def checkSign(self, mess, result, pubkey=None):
        """
        验证签名：传入解密后明文、签名、公钥，验证成功返回哈希方法，失败则报错
        :param mess: str
        :param result: bytes
        :param pubkey: 
        :return: str
        """
        if None == pubkey:
            pubkey = self.privkey
        try:
            result = rsa.verify(mess, result, pubkey)
            return result
        except:
            return False


def USE_MD5(message):
    if not isinstance(message, bytes):
        message = bytes(message, 'utf-8')
    m = hashlib.md5()
    m.update(message)
    return m.hexdigest()


def USE_TIME():
    stamp = int(time.time())
    return stamp


if __name__ == '__main__':
    # MD5_ALG = "suchen"
    # rsa_alg = USE_RSA()
    # SECRET_ABSTRACT = rsa_alg.RSA_ENCRYPT(MD5_ALG)
    # print("加密后为：")
    # print(SECRET_ABSTRACT)
    # ABSTRACT = rsa_alg.RSA_DECRYPT(SECRET_ABSTRACT)
    # print(ABSTRACT)
    print(USE_RSA("a.pem", "b.pem").pubkey)
    print(USE_RSA("a.pem", "b.pem").privkey)
