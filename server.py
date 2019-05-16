# -*-coding:utf-8-*-

# 服务端

import socket
import threading
import json
from Pipline import DecodePipline


def clientThreadIn(conn, nick):
    global data
    while True:
        try:
            temp = conn.recv(2048)  # 客户端发过来的消息
            if not temp:
                conn.close()
                return
            NotifyAll(temp)
            DecodePipline(data)
        except:
            NotifyAll("Something Wrong ! " + nick + ' leaves the room')  # 出现异常就退出
            continue


def clientThreadOut(conn, nick):
    global data
    while True:
        if con.acquire():
            con.wait()  # 堵塞，放弃对资源的占有  等待通知运行后面的代码
            if data:
                try:
                    conn.send(data)
                    con.release()
                except:
                    con.release
                    return


def NotifyAll(ss):
    global data
    if con.acquire():  # 获取锁
        data = ss
        con.notifyAll()  # 当前线程放弃对资源的占有，通知所有等待x线程
        con.release()


con = threading.Condition()  # 条件
Host = '127.0.0.1'  # ip地址
port = 5000
data = ''

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建套接字
print('Socket created')
s.bind((Host, port))  # 把套接字绑定到ip地址
s.listen(500)
print('Socket now listening')

while True:
    conn, addr = s.accept()  # 接受连接
    print('Connected with' + '' + addr[0] + ':' + str(addr[1]))  # 字符串拼接
    nick = conn.recv(1024).decode()  # 获取用户名
    NotifyAll('Welcome' + ' ' + nick + ' to the room!')
    print(str((threading.activeCount() + 1) / 2) + 'person(s)')
    conn.sendall(data.encode('utf-8'))
    threading.Thread(target=clientThreadIn, args=(conn, nick)).start()
    threading.Thread(target=clientThreadOut, args=(conn, nick)).start()

