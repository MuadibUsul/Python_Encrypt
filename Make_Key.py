import rsa

f, e = rsa.newkeys(2048)  # 生成公钥、私钥

e = e.save_pkcs1()  # 保存为 .pem 格式
with open("a.pem", "wb") as x:  # 保存私钥
    x.write(e)
f = f.save_pkcs1()  # 保存为 .pem 格式
with open("b.pem", "wb") as x:  # 保存公钥
    x.write(f)