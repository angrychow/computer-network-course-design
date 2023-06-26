#include<stdio.h>
#include <stdint.h>
#include<string.h>

typedef struct Ipset {
    int num;//ipSet的ip个数
    uint32_t ip[50 + 5];//该set存储的ip
} Ipset;
Ipset ipset[1000 + 5];
int domainName_num;

int trie_search(char * domainName);
int trie_insert(char * domainName, uint32_t ipv4);
