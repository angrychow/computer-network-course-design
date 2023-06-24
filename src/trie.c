#include<stdio.h>
#include <stdint.h>
#include<string.h>

typedef struct Node {
    char ch;
    uint32_t ipv4;
    int son[130];
    int end;
} Node;
Node node[1000 + 5];
int node_num = 1;

void DFS_insert(int u, int dep, char * domainName, uint32_t ipv4) {
    if(dep == strlen(domainName) ) {
        node[u].end = 1;
        node[u].ipv4 = ipv4;
        return;
    }
    else {
        node[u].end = 0;
        node[u].ipv4 = UINT32_MAX;
    }

    if(node[u].son[ domainName[dep] ] == 0)
        node[u].son[ domainName[dep] ] = ++ node_num;

    u = node[u].son[ domainName[dep] ];
    DFS_insert(u, dep + 1, domainName, ipv4);
}

uint32_t DFS_search(int u, int dep, char * domainName) {
    if(dep == strlen(domainName)) {
        if(node[u].end == 1)
            return node[u].ipv4;
        if(node[u].end == 0)
            return UINT32_MAX;
    }
    
    if(node[u].son[ domainName[dep] ] == 0)
        return UINT32_MAX;
    else
        DFS_search(node[u].son[ domainName[dep] ], dep + 1, domainName);
}

uint32_t trie_search(char * domainName) {
    return DFS_search(1, 0, domainName);
}

int trie_insert(char * domainName, uint32_t ipv4) {
    if(trie_search(domainName) != UINT32_MAX)//已经存在域名，不可重复加入
        return 0;
    DFS_insert(1, 0, domainName, ipv4);
    return 1;
}
