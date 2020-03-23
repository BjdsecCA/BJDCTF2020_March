#!/bin/sh
echo "ctf:guest" | chpasswd
chown -R root:root /home/ctf/
chown root:ctf_pwn /home/ctf/flag
chown root:ctf_pwn /home/ctf/main.c /home/ctf/data.h
chown root:ctf_pwn /home/ctf/record /home/ctf/msg
chown root:ctf_pwn /home/ctf/els
chmod 640 /home/ctf/flag
chmod 644 /home/ctf/main.c /home/ctf/data.h
chmod 664 /home/ctf/record
chmod 666 /home/ctf/msg
chmod 2555 /home/ctf/els

/usr/sbin/sshd -D
