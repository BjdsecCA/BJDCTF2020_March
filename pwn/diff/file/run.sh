#!/bin/sh
echo "ctf:guest" | chpasswd
chown -R root:root /home/ctf/
chown root:ctf_pwn /home/ctf/flag
chown root:ctf_pwn /home/ctf/diff
chmod 640 /home/ctf/flag
chmod 2555 /home/ctf/diff

/usr/sbin/sshd -D

