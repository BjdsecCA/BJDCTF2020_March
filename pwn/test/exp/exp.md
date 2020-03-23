# test
测试ssh连接显示字符什么的是否正常，直接cat flag太简单了，就加了个小过滤，不能使用含有`nepbushiflag`字符的命令

## 找可用命令
```
$ env $PATH
$ ls /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin /usr/games /usr/local/games | grep -v -E 'n|e|p|b|u|s|h|i|f|l|a|g'
```

## od
od可用
```
ctf@f930cab87217:~$ ./test | grep 045102 -C 2
od *
uid=1000(ctf) gid=1000(ctf) egid=1001(ctf_pwn) groups=1000(ctf)
0000000 045102 075504 067145 067552 057571 067571 071165 070137
0000020 067167 063537 066541 076545 077412 046105 001106 000401
0000040 000000 000000 000000 000000 001000 037000 000400 000000

```

解八进制编码即可得到flag

