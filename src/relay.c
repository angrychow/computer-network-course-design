#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>  // for open
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h> // for close

#include "relay.h"
#include "dns.h"
#include "shared_resource.h"

#define BUFF_SIZE 1024

uint8_t* relayDNSPacket(uint8_t* packet, uint8_t* ip) {
  int sockfd;
  struct sockaddr_in server_addr;
  int ret = 0;
  int c = 0;
  // char buff[BUFF_SIZE] = {'\0'};
  uint8_t* buff = malloc(BUFF_SIZE);
  socklen_t addr_len;

  // 创建一个套接字
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  // 设置服务器地址
  server_addr.sin_family = AF_INET;
  printf("relay server ip: %s\n",getRelayServerIP());
  server_addr.sin_addr.s_addr = inet_addr(getRelayServerIP());
  server_addr.sin_port = htons(53);

  // ret =
  //     bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
  // if (-1 == ret) {
  //   perror("bind");
  //   exit(1);
  // }


  // ID 判重，注意到这里是 Critical Area 🤮
  uint8_t *message = packet;
  struct DNS_HEADER *reqHeader = (struct DNS_HEADER *)message;
  // 取出本地 ID
  uint16_t localID = ntohs(reqHeader->ID);
  // 中继 ID
  uint16_t relayID;

  // 获取锁，查询可用 id
  pthread_mutex_lock(getRWLock());

  if ((getIdTable())[localID] == 0) {
    (getIdTable())[localID] = 1;
    relayID = localID;
  } else {
    for (int i = 0; i < (1 << 16); i++) {
      if ((getIdTable())[i] == 0) {
        relayID = i;
        break;
      }
    }
  }

  // 归还锁
  pthread_mutex_unlock(getRWLock());

  // 修改表头
  reqHeader->ID = htons(relayID);

  // 设置 recv 超时时间 1s

  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
    perror("Error");
    pthread_exit(NULL);
  }

  
  // 向服务器发送数据
  ret = sendto(sockfd, message, 1024, 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr));
  if (-1 == ret) {
    perror("sendto");
    pthread_exit(NULL);
  }

  printf("send %d bytes to isp dns server \n", ret);

  // 接收服务器发送的数据
  ret = recv(sockfd, buff, 1024, 0);
  // 没得到数据（超时也返回 -1 ），直接让线程挂掉，服务端超时，会进行第二次 dns probe
  if (-1 == ret) {
    printf("Timeout or UDP Failed. Thread %ld exit.", pthread_self());
    perror("recv");
    pthread_exit(NULL);
  }
  printf("received %d bytes from isp dns server\n", ret);

  // 获取锁，将原本的 id 号归还，修改 resp id
  pthread_mutex_lock(getRWLock());
  (getIdTable())[relayID] = 0;
  struct DNS_HEADER *respHeader = (struct DNS_HEADER *)buff;
  respHeader->ID = localID;
  // 归还锁
  pthread_mutex_unlock(getRWLock());
  return buff;
}
