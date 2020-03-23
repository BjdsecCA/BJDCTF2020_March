#!/bin/sh
echo "ctf:test" | chpasswd
chown -R root:root /home/ctf/
chown root:ctf_pwn /home/ctf/flag
chown root:ctf_pwn /home/ctf/test.c
chown root:ctf_pwn /home/ctf/test
chmod 640 /home/ctf/flag
chmod 644 /home/ctf/test.c
chmod 2555 /home/ctf/test

/usr/sbin/sshd -D
