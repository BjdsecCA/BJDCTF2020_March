FROM ubuntu:19.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list 
RUN apt-get update && apt-get -y dist-upgrade
RUN apt-get install -y python python-pip

RUN pip install pycrypto -i "https://pypi.doubanio.com/simple/"

RUN useradd -m ctf

WORKDIR /home/ctf

COPY ./start.sh /start.sh

RUN chmod +x /start.sh

COPY ./bin/ /home/ctf/
RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf 

CMD ["/start.sh"]

EXPOSE 8888
