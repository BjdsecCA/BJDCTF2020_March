FROM ubuntu:14.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y ssh

RUN useradd -m -s /bin/bash ctf
RUN useradd -m ctf_pwn

WORKDIR /home/ctf

COPY ./file/bin /home/ctf/
COPY ./file/run.sh /run.sh

COPY ./file/bin /home/ctf
COPY ./file/config/motd /etc/motd
COPY ./file/config/issue /etc/issue
COPY ./file/config/legal /etc/legal
COPY ./file/config/motd.dynamic /var/run/motd.dynamic
COPY ./file/config/sshd_config /etc/ssh/sshd_config

RUN mkdir -p /var/run/sshd
RUN chmod +x /run.sh

RUN echo "ctf:guest" | chpasswd
RUN chown -R root:root /home/ctf/ && \
    chown root:ctf_pwn /home/ctf/flag && \
    chown root:ctf_pwn /home/ctf/test.c && \
    chown root:ctf_pwn /home/ctf/test && \
    chmod 640 /home/ctf/flag && \
    chmod 644 /home/ctf/test.c && \
    chmod 2555 /home/ctf/test

CMD ["/run.sh"]

EXPOSE 22

