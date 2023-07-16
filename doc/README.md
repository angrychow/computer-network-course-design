本程序在 WSL 环境下进行编译。

将目录切换至 /src 文件夹下，并执行：

```
gcc analyze.c relay.c server.c shared_resource.c trie.c -lpthread -o dns
```

即可进行编译。