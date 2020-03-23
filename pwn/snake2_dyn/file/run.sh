#!/bin/sh
echo "ctf:sNaKes" | chpasswd
chown -R root:root /home/ctf/
qrencode -m 2 -t ASCII < /home/ctf/flag > /home/ctf/fakeflag
sed -i "s/ /./g" /home/ctf/fakeflag
cat /home/ctf/fakeflag > /home/ctf/flag
rm -rf /home/ctf/fakeflag
chmod 640 /home/ctf/flag
chown root:ctf_pwn /home/ctf/flag
chown root:ctf_pwn /home/ctf/flag
chown root:ctf_pwn /home/ctf/snake
chown root:ctf_pwn /home/ctf/snake.c
chmod 2555 /home/ctf/snake
chmod 644 /home/ctf/snake.c

/usr/sbin/sshd -D
