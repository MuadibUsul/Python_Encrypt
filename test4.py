import rsa

y = b"abcdefg1234567"

with open("e.pem", "rb") as x:
    e = x.read()
    e = rsa.PrivateKey.load_pkcs1(e)  # load 私钥
with open("f.pem", "rb") as x:
    f = x.read()
    f = rsa.PublicKey.load_pkcs1(f)   # load 公钥，由于之前生成的私钥缺少'RSA'字段，故无法 load

cipher_text = rsa.encrypt(y, f)  # 使用公钥加密
text = rsa.decrypt(cipher_text, e)  # 使用私钥解密
assert text == y  # 断言验证

sign = rsa.sign(y, e, "MD5")  # 使用私钥进行'sha256'签名
verify = rsa.verify(y, sign, f)  # 使用公钥验证签名
print(verify)