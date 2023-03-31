#include "./dns.h"

void setReplyHeader(struct DNS_HEADER* header, uint16_t ID) {
  header->ID = ID;         // from Query
  header->QueryReply = 1;  // 指定为回复
  // printf("%x\n", &(header->QueryReply) - header);
  header->OPCode = 0;
  header->AuthoritativeRequest = 0;
  header->Truncate = 0;
  header->RecursionDesired = 1;
  header->RecursionAvailable = 1;
  header->Zero = 0;
  header->ResponseCode = 0;  // 没有错误
  // 避免大小端，直接操纵字节
  header->QDCOUNT_HIGH = 0;
  header->QDCOUNT_LOW = 1;
  header->ANCOUNT_HIGH = 0;
  header->ANCOUNT_LOW = 1;
  header->NSCOUNT = 0;
  header->ARCOUNT = 0;
  printf("\n");
  uint8_t* cast = (uint8_t*)header;
  for (int i = 0; i < 12; i++) {
    printf("%x ", cast[i]);
  }
  printf("\n above is header");
}

uint8_t* analyzeRequest(uint8_t* buf) {
  uint16_t ID = *(uint16_t*)buf;
  printf("ID:%x\n", ID);
  uint8_t* ret = malloc(1024 * sizeof(uint8_t));
  // 保存指针的起点
  uint8_t* originRet = ret;
  uint16_t queryType;
  uint16_t queryClass;
  // 设置回复头部
  struct DNS_HEADER* respHeader = (struct DNS_HEADER*)ret;
  setReplyHeader(respHeader, ID);
  uint8_t urlSet[64][64] = {'\0'};
  int urlCnt = 0;
  printf("sizeof DNS_HEADER:%d\n", sizeof(struct DNS_HEADER));
  // 偏移到 question 部
  uint8_t* reqQustion = buf + LEN_DNS_HEADER;
  ret += LEN_DNS_HEADER;
  // 遍历 url
  while (1) {
    *ret = *reqQustion;
    int count = *reqQustion;
    ret++;
    reqQustion++;
    if (count == 0) {
      break;
    }
    for (int i = 0; i < count; i++) {
      *ret = *reqQustion;
      urlSet[urlCnt][i] = *reqQustion;
      ret++;
      reqQustion++;
    }
    urlCnt++;
  }
  // 设置 query Type && query Class
  uint16_t* reqQuestionCast = (uint16_t*)reqQustion;
  uint16_t* retCast = (uint16_t*)ret;
  queryType = *reqQuestionCast;
  *retCast = queryType;
  printf("queryType:%d\n",queryType);
  reqQuestionCast++;retCast++;
  queryClass = *reqQuestionCast;
  *retCast = queryClass;
  reqQustion += 4;ret += 4;
  for (int i = 1; i <= urlCnt; i++)
    printf("%s\n", urlSet[i - 1]);
  // 设置 Answer，TODO：从 HOST 抽取 / 114.114.114.114 转发

  // offset
  *ret = 0xc0;ret ++;
  *ret = 0x0c;ret ++;

  // Type
  uint16_t* retCastAgain = (uint16_t*)ret;
  *retCastAgain = queryType;
  ret+=2;
  // Protocol
  *ret=0x00;ret++;
  *ret=0x01;ret++;
  // TTL
  *ret=0x00;ret++;
  *ret=0x00;ret++;
  *ret=0x02;ret++;
  *ret=0x58;ret++;

  // Addr. Length
  *ret = 0x00;ret++;
  if(queryType==7168) {
    *ret = 0x06;ret++;//IPV6
  } else {
    *ret = 0x04;ret++;//IPV4
  }
  

  // Addr.
  *ret = 0x7f;ret++;
  *ret = 0x00;ret++;
  *ret = 0x00;ret++;
  *ret = 0x01;
  return originRet;
}
