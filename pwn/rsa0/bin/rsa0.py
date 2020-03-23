#!/usr/bin/python
#__author__:TaQini
from Crypto.Util.number import *
import random
import socket 

flag = bytes_to_long(open("/home/ctf/flag").read())

p=getPrime(512)
q=getPrime(512)
e=getPrime(24)
N = p*q

c = pow(flag, e, N)

s = socket.socket()
host = '0.0.0.0' # socket.gethostname()
port = 8888
s.bind((host, port))

s.listen(5)
while True:
    con,addr = s.accept()
    con.send('e='+str(e)+'\n\n')
    con.send('p+q='+str(p+q)+'\n\n')
    con.send('p-q='+str(p-q)+'\n\n')
    con.send('c='+str(c)+'\n\n')
    con.send('flag=??????\n\n')
    con.close() 
