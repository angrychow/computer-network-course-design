#include<stdio.h>
#include <stdint.h>
#include<string.h>
#include "trie.h"

typedef struct Node {
    int son[130];
    int end;
    int id;//映射到下标为id的ipv4地址集合
} Node;
Node node[1000 + 5];
int node_num = 1;

int domainName_num;

void DFS_insert(int u, int dep, char * domainName, uint32_t ipv4) {
    if(dep == strlen(domainName) ) {
        node[u].end = 1;
        if(node[u].id == 0)
            node[u].id = ++ domainName_num;
        ipset[domainName_num].num ++;
        ipset[domainName_num].ip[ ipset[domainName_num].num ] = ipv4;
        return;
    }
    else {
        node[u].end = 0;
        node[u].id = 1;
    }

    if(node[u].son[ domainName[dep] ] == 0)
        node[u].son[ domainName[dep] ] = ++ node_num;

    u = node[u].son[ domainName[dep] ];
    DFS_insert(u, dep + 1, domainName, ipv4);
}

int DFS_search(int u, int dep, char * domainName) {
    if(dep == strlen(domainName)) {
        if(node[u].end == 1)
            return node[u].id;
        if(node[u].end == 0)
            return 0;
    }
    
    if(node[u].son[ domainName[dep] ] == 0)
        return 0;
    else
        DFS_search(node[u].son[ domainName[dep] ], dep + 1, domainName);
}

int trie_search(char * domainName) {
    return DFS_search(1, 0, domainName);
}

int trie_insert(char * domainName, uint32_t ipv4) {
    DFS_insert(1, 0, domainName, ipv4);
    return 1;
}

// int main() {
//     trie_insert("www.baidu.com", 32);
//     printf("%d\n", trie_search("www.baidu.com"));
//     printf("%d\n", trie_search("www.badu.com"));
//     return 0;
// }
