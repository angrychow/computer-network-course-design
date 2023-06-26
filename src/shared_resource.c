
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "shared_resource.h"
#include "server.h"
#include "trie.h"

pthread_mutex_t id_tabel_lock;

struct INTERCEPTOR_TABLE* urlTable;
uint8_t *idTable;
uint32_t urlTableNumber=0;

void initSharedResource() {
  printf("blocklist url: \n");
  urlTable = (struct INTERCEPTOR_TABLE*) malloc(sizeof(struct INTERCEPTOR_TABLE) * 1024);
  idTable = malloc(sizeof(uint8_t) * (1 << 16));
  pthread_mutex_init(&id_tabel_lock,NULL);
  
  char* blocklist = getBlockList();
 
  printf("%s\n",blocklist);
  FILE *fp = fopen(getBlockList(), "r");
  
  if (fp == NULL) {
    printf("no such file!");
    exit(0);
  }
  char ipv4[32] = {'\0'};
  char url[128] = {'\0'};
  while (fscanf(fp, "%s", ipv4) != EOF) {
    fscanf(fp, "%s", url);
    int temp[4] = {0};
    char *tmp = malloc(128);
    char *trueUrl = tmp;
    int dotCnt[128] = {0};
    int cnt = 0;
    uint32_t trueIpv4 = 0;
    for (int i = 0; ipv4[i] != '\0'; i++) {
      if (ipv4[i] == '.') {
        cnt ++;
      } else {
        temp[cnt] = 10 * temp[cnt] + (ipv4[i] - '0');
      }
    }
    trueIpv4 = temp[0] * 256 * 256 * 256 + temp[1] * 256 * 256 + temp[2] * 256 +
               temp[3];
    for (int i = 0; url[i] != '\0'; i++) {
      if (url[i] == '.')
        dotCnt[0]++;
      else
        dotCnt[dotCnt[0] + 1]++;
    }
    dotCnt[0]++;
    {
      int tmpCnt = 0;
      int urlCnt = 0;
      for (int i = 1; i <= dotCnt[0]; i++) {
        tmp[tmpCnt++] = (char)('0'+dotCnt[i]);
        while (url[urlCnt] != '.' && url[urlCnt] != '\0') {
          tmp[tmpCnt++] = url[urlCnt++];
        }
        if (url[urlCnt] == '\0') {
          break;
        } else if(url[urlCnt] == '.') urlCnt++;
      }
      tmp[tmpCnt] = '0';
    }
    urlTable[urlTableNumber].domainName = tmp;
    urlTable[urlTableNumber++].ipv4 = trueIpv4;
    trie_insert(tmp, trueIpv4);
    printf("%ud %s\n", trueIpv4, tmp);
  }

  
}
struct INTERCEPTOR_TABLE *getUrlTable() { return urlTable; }

pthread_mutex_t* getRWLock() { return &id_tabel_lock; }

uint8_t *getIdTable() { return idTable; }

uint8_t checkUrl(char *url) {
  // for (int i = 0; i < urlTableNumber; i++) {
  //   if (!strcmp(url, urlTable[i].domainName)) {
  //     return 1;
  //   }
  // }
  // return 0;
  int ret = trie_search(url);
  if(ret == 0)
    return 0;
  else
    return 1;
}

int getUrl(char *url) {
  // for (int i = 0; i < urlTableNumber; i++) {
  //   if (!strcmp(url, urlTable[i].domainName)) {
  //     return urlTable[i].ipv4;
  //   }
  // }
  // return 0;
  return trie_search(url);
}
