#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define LEN_DNS_HEADER sizeof(struct DNS_HEADER)
#define LEN_DNS_QUESTION sizeof(struct DNS_QUESTION)
#define LEN_DNS_ANSWER sizeof(struct DNS_ANSWER)
#define AUTH_COUNT 0x0
#define ADD_COUNT 0x0
#define IP_PORT 53
#define IP_ADDR "192.168.0.1"
#define TTL 0x00000300
#define QUERY_TYPE_AAAA 7168
#define QUERY_TYPE_A 256
// #pragma pack(push, 1)
struct DNS_HEADER {
  // unsigned char id1;          // 会话id
  // unsigned char id2;          // 会话id
  uint16_t ID;
  // 经检验，这里从字节低位排到字节高位，struct 顺序与协议顺序相反
  uint8_t RecursionDesired : 1;
  uint8_t Truncate : 1;
  uint8_t AuthoritativeRequest : 1;
  uint8_t OPCode : 4;
  uint8_t QueryReply : 1;
  // 经检验，这里从字节低位排到字节高位，struct 顺序与协议顺序相反
  uint8_t ResponseCode : 4;
  uint8_t Zero : 3;
  uint8_t RecursionAvailable : 1;
  // 避免大小端
  // uint8_t QDCOUNT_HIGH;
  // uint8_t QDCOUNT_LOW;
  uint16_t QDCOUNT;
  // uint8_t ANCOUNT_HIGH;
  // uint8_t ANCOUNT_LOW;
  uint16_t ANCOUNT;
  uint16_t NSCOUNT;
  uint16_t ARCOUNT;
} __attribute__((packed));
// #pragma pack(pop)
// 查询字段
struct DNS_QUESTION {
  unsigned short qtype;
  unsigned short qclass;
};
// 回答字段
// #pragma pack(push, 1)
struct DNS_ANSWER {
  unsigned short answer_name;
  unsigned short answer_type;
  unsigned short answer_class;
  unsigned int time_live;
  unsigned short DL;
};

struct my_dns {
  char name[20];
  char ip[20];
};

struct QUERY_ANS {
  uint16_t QUERY_TYPE;
  uint16_t QUERY_CLASS;
};

