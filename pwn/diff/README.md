# bjd diff

## build
```
sudo docker-compose build
```
you will get image `taqini/bjd_diff`

## deploy
change default port(1000x) in `docker-compose.yml`
then:
```
sudo docker-compose up -d
```

> you can modify file in docker by modfiy the file in folder `file`, 
> because files are mounted by the configuartion in compose file
> so, you can patch binary or change the motd/issue of sshd
