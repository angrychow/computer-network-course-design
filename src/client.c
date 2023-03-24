#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>  // for open
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>  // for close

#define BUFF_SIZE 1024

int main(int argc, char** argv) {
  int sockfd;
  struct sockaddr_in server_addr;
  int ret = 0;
  int c = 0;
  char buff[BUFF_SIZE] = {'\0'};
  socklen_t addr_len;

  if (argc < 2) {
    fprintf(stderr, "missing parameter!\n");
    exit(1);
  }

  // 创建一个套接字
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  // 设置服务器地址
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  server_addr.sin_port = htons(8888);

  // 向服务器发送数据
  // strcpy(buff, "hello world");
  char* message = argv[1];
  ret = sendto(sockfd, message, strlen(message) + 1, 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr));
  if (-1 == ret) {
    perror("sendto");
    exit(errno);
  }

  printf("send %d bytes\n", ret);

  // 接收服务器发送的数据
  ret = recv(sockfd, buff, sizeof(buff), 0);
  if (-1 == ret) {
    perror("recvfrom");
    exit(errno);
  }

  printf("received %d bytes\n", ret);
  printf("recevied: %s\n", buff);

  return 0;
}