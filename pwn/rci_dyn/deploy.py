#!/usr/bin/python
#__author__:TaQini
from os import listdir
from os import system
from sys import argv

ctf_xinetd = '''
service ctf
{
    disable = no
    socket_type = stream
    protocol    = tcp
    wait        = no
    user        = root
    type        = UNLISTED
    port        = 9999
    bind        = 0.0.0.0
    server      = /usr/sbin/chroot
    # replace helloworld to your program
    server_args = --userspec=1000:1000 /home/ctf ./%s
    banner_fail = /etc/banner_fail
    # safety options
    per_source  = 10 # the maximum instances of this service per source IP address
    rlimit_cpu  = 20 # the maximum number of CPU seconds that the service may use
    #rlimit_as  = 1024M # the Address Space resource limit for the service
    #access_times = 2:00-9:00 12:00-24:00
}
'''

usage = '''
usage:
    ./deploy.py your_pwn_challenge docker_REPOSITORY_name
'''

if len(argv)!=3:
    print(usage)
else:
    print("[+] copying pwn challenge...")
    cp = 'cp %s ./bin/'
    pwn_file = argv[1]
    system(cp%pwn_file)
    print("[-] Done!")

    print("[+] generating ./ctf.xinetd...")
    f = open('./ctf.xinetd','w')
    f.write(ctf_xinetd%listdir('./bin')[0])
    f.close()
    print("[-] Done!")

    print("[+] building docker image...")
    cmd = 'sudo docker build -t "%s" .'
    repo_name = argv[2]
    system(cmd%repo_name)
    print("[-] Done!")

    print("[+] cleaning tmp file...")
    clean = 'rm -f ./bin/* ./ctf.xinetd'
    system(clean)
    print("[-] Done!")
