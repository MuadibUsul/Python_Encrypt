import json
from CryptTool import *
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)  # Log等级总开关
# 第二步，创建一个handler，用于写入日志文件
logfile = './log/logger.txt'
fh = logging.FileHandler(logfile, mode='w')
fh.setLevel(logging.DEBUG)  # 输出到file的log等级的开关

# 第三步，再创建一个handler，用于输出到控制台
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)  # 输出到console的log等级的开关

# 第四步，定义handler的输出格式
formatter = logging.Formatter("%(asctime)s - %(filename)s- %(levelname)s: %(message)s")
fh.setFormatter(formatter)
ch.setFormatter(formatter)

# 第五步，将logger添加到handler里面
logger.addHandler(fh)
logger.addHandler(ch)


def EncodePipline(msg):
    message = {}

    # file_path = "./message.txt"
    # msg = ''
    # FILE = open(file_path, "r", encoding='utf-8')
    # content = FILE.readlines()
    # FILE.close()
    # for line in content:
    #     msg = msg + line
    '''使用AES对称加密算法加密明文'''
    AES_KEY = "suchenzhendeshuai"
    aes_alg = USE_AES(AES_KEY)
    logger.info("AES加密明文开始")
    message["SECRET_MSG"] = str(aes_alg.AES_ECRYPT(msg))
    logger.info("AES加密明文成功")
    logger.info(message["SECRET_MSG"])
    # AES解密方法
    # msg = aes_alg.AES_DECRYPT(message["SECRET_MSG"])

    '''MD5计算明文摘要'''
    message["MD5_ALG"] = str(USE_MD5(msg))
    logger.info("明文的MD5摘要为：")
    logger.info(message["MD5_ALG"])

    '''使用私钥a加密摘要'''
    rsa_alg = USE_RSA("a.pem", "b.pem")
    message["SECRET_ABSTRACT"] = str(rsa_alg.RSA_ENCRYPT(message["MD5_ALG"], 0))
    logger.info("加密后的MD5摘要为：")
    logger.info(message["SECRET_ABSTRACT"])
    # 解密
    # ABSTRACT = rsa_alg.RSA_DECRYPT(SECRET_ABSTRACT)
    # print(ABSTRACT)

    '''使用公钥B加密AES密码'''
    rsa_alg = USE_RSA("e.pem", "f.pem")
    message["SECRET_KEY"] = str(rsa_alg.RSA_ENCRYPT(AES_KEY, 1))
    logger.info("加密后的AES秘钥为：")
    logger.info(message["SECRET_KEY"])

    # AES_KEY = rsa_alg.RSA_DECRYPT(SECRET_KEY)
    # print(AES_KEY)
    '''获取时间戳'''
    message["TIME_STAMP"] = str(USE_TIME())
    logger.info("目前时间为：")
    logger.info(message["TIME_STAMP"])
    '''拼接字段'''
    message = json.dumps(message, skipkeys=True, indent=4)
    return message


def DecodePipline(msg):
    msg = json.loads(msg)

    stamp = int(msg["TIME_STAMP"])
    nowtime = int(time.time())
    if nowtime < (stamp + 5):
        logger.info("Timestamp Validation!")
    else:
        logger.info("Time Out, Try Again!")

    # 解密加密后的AES 密钥
    rsa_alg1 = USE_RSA("e.pem", "f.pem")
    AES_KEY = rsa_alg1.RSA_DECRYPT(msg["SECRET_KEY"].encode("utf-8"), 1)
    logger.info("获取AES密钥：")
    logger.info(AES_KEY)

    # 解密加密后的摘要
    print(msg["SECRET_ABSTRACT"])
    print(type(msg["SECRET_ABSTRACT"]))
    rsa_alg2 = USE_RSA("a.pem", "b.pem")
    abstract = rsa_alg2.RSA_DECRYPT(msg["SECRET_ABSTRACT"], 0)
    logger.info("获取摘要：")
    logger.info(abstract)

    # 解密加密后的正文
    aes_alg = USE_AES(AES_KEY)
    message = aes_alg.AES_DECRYPT(msg["SECRET_MSG"])
    logger.info("获取正文：")
    logger.info(message)

    # 对正文进行摘要
    message_md5 = USE_MD5(message)

    # 比对正文摘要与传输过来的摘要
    if message_md5 == abstract:
        logger.info("完整性验证通过")
    else:
        logger.info("完整性验证失败")


if __name__ == '__main__':
    x =EncodePipline("suchen")
    DecodePipline(x)


