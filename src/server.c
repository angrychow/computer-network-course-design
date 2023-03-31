#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>  // for open
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>  // for close
#include "./analyze.h"

#define BUFF_SIZE 1024
#define THREAD_SIZE 1024
#define PRINT_SIZE 256

struct args {
  struct args* next;
  void* arg;
};

// 英文小写转换成大写
static void str2up(char* str) {
  while (*str) {
    if (*str >= 'a' && *str <= 'z') {
      *str = *str - 'a' + 'A';
    }

    str++;
  }
}

int server_sockfd;
pthread_t threadID[THREAD_SIZE] = {0};
int countThread = 0;

void* handleRecv(void* args) {
  struct args* castArgs = (struct args*)args;
  struct sockaddr_in* clientAddr = (struct sockaddr_in*)castArgs->arg;
  // 释放 1
  struct args* prevCastArgs = castArgs;
  castArgs = castArgs->next;
  free(prevCastArgs);
  int* clientAddrLen = (int*)castArgs->arg;
  // 释放 2
  prevCastArgs = castArgs;
  castArgs = castArgs->next;
  free(prevCastArgs);
  uint8_t* buff = (uint8_t*)castArgs->arg;

  // printf("thread - %s\n", buff);
  printf("thread output:\n");
  // int stringLength = strlen(buff);
  // printf("String Length: %d\n", stringLength);
  for (int i = 0; i < PRINT_SIZE; i++) {
    if (buff[i] < 16)
      printf("0");
    printf("%x ", buff[i]);
    // if (i % 2 == 1)
    // printf(" ");
    if (i % 32 == 31)
      printf("\n");
  }
  printf("\n");
  // 处理
  uint8_t* reply = analyzeRequest(buff);
  for (int i = 0; i < PRINT_SIZE; i++) {
    if (reply[i] < 10)
      printf("0");
    printf("%x ", reply[i]);
    // if (i % 2 == 1)
    // printf(" ");
    if (i % 32 == 31)
      printf("\n");
  }
  printf("\n");
  int send_len = 0;
  send_len = sendto(server_sockfd, (char*)reply, 128, 0,
                    (struct sockaddr*)clientAddr, *clientAddrLen);
  if (-1 == send_len) {
    perror("sendto");
    exit(errno);
  }
  free(buff);
  free(reply);
  free(clientAddr);
  free(clientAddrLen);
  return NULL;
}

int main(void) {
  int ret = 0;
  int recv_len = 0;

  // char buff[BUFF_SIZE] = {'\0'};

  // 用于UNIX系统内部通信的地址， struct sockaddr_un
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  int client_addr_len = sizeof(struct sockaddr_in);

  server_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  // 设置服务器地址
  server_addr.sin_family =
      AF_INET;  // 地址的域， 相当于地址的类型， AF_UNIX表示地址位于UNIX系统内部
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(53);

  // 绑定该套接字，使得该套接字和对应的系统套接字文件关联起来
  ret =
      bind(server_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
  if (-1 == ret) {
    perror("bind");
    exit(1);
  }

  // 循环处理客户端请求
  while (1) {
    printf("server waiting\n");

    char* buff = malloc(sizeof(char) * BUFF_SIZE);
    recv_len = recvfrom(server_sockfd, buff, 1024 * sizeof(char), 0,
                        (struct sockaddr*)&client_addr, &client_addr_len);
    if (recv_len < 0) {
      perror("recvfrom");
      exit(errno);
    }
    // 初始化参数列表
    struct args* argCliAddr = malloc(sizeof(struct args));
    struct args* argAddrLen = malloc(sizeof(struct args));
    struct args* argBuff = malloc(sizeof(struct args));
    // 参数 client_addr 注入
    struct sockaddr_in* clientAddrPass = malloc(sizeof(struct sockaddr_in));
    *clientAddrPass = client_addr;
    argCliAddr->arg = (void*)clientAddrPass;
    argCliAddr->next = argAddrLen;
    // 参数 client_addr_len 注入
    int* clientAddrLenPass = malloc(sizeof(int));
    *clientAddrLenPass = client_addr_len;
    argAddrLen->arg = (void*)clientAddrLenPass;
    argAddrLen->next = argBuff;
    // 参数 buff 注入
    argBuff->arg = (void*)buff;
    // 线程 join，等待释放
    countThread = (countThread + 1) % THREAD_SIZE;
    if (threadID[countThread]) {
      pthread_join(threadID[countThread], (void**)0);
    }
    pthread_create(&threadID[countThread], NULL, handleRecv, (void*)argCliAddr);
  }

  close(server_sockfd);
  return 0;
}