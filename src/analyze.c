#include "dns.h"
#include "shared_resource.h"
#include "relay.h"
#include "trie.h"
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>

//根据114.114.114.114发过来的报文进行本地存储
void cache_store(uint8_t * buff, char * domainName, int qname_length) {
  uint8_t * tmp = (buff + LEN_DNS_HEADER + qname_length + LEN_DNS_QUESTION);
  uint32_t * ipv4;
  struct DNS_HEADER * header = (struct DNS_HEADER *) buff;
  uint16_t ANCOUNT = header -> ANCOUNT;
  int cnt = 0;
  while(1) {//跳过TYPE为CNAME的ANSWER，取得第一个TYPE为A的ANSWER的RDATA字段
    uint8_t * name = tmp;
    int name_length = 0;
    while(1) {
      name_length ++;
      if(*name == 0) break;
      if(*name == 0xc0) {
        name_length ++;
        break;
      }
      name ++;
    }

    uint16_t * TYPE = (uint16_t * )(tmp + name_length);
    uint16_t * rd_length = (uint16_t *)(tmp + name_length + 8);
    if(ntohs(*TYPE) == 1) {//回答为A
      ipv4 = (uint32_t *)(tmp + name_length + 10);
      trie_insert(domainName, ntohl(*ipv4));
    }
    tmp = (tmp + name_length + 10 + ntohs(*rd_length));
    cnt ++;
    if(cnt == ANCOUNT) break;
  }

}

void setReplyHeader(struct DNS_HEADER* header, uint16_t ID) {
  header->ID = ID;         // from Query
  header->QueryReply = 1; // 指定为回复
  header->OPCode = 0;
  header->AuthoritativeRequest = 0;
  header->Truncate = 0;
  header->RecursionDesired = 1;
  header->RecursionAvailable = 1;
  header->Zero = 0;
  header->ResponseCode = 0;  // 没有错误
  uint16_t local_qdcount = 0x0001;
  uint16_t local_ancount = 0x0001;
  header->QDCOUNT = htons(local_qdcount);
  header->ANCOUNT = htons(local_ancount);
  header->NSCOUNT = 0;
  header->ARCOUNT = 0;
  uint8_t* cast = (uint8_t*)header;
  for (int i = 0; i < 12; i++) {
    printf("%x ", cast[i]);
  }
  printf("\n above is header \n");
}

uint8_t *analyzeRequest(uint8_t *buf) {

  uint8_t isRelay = 0;
  
  uint16_t ID = *(uint16_t *)buf;
  // 请求头
  struct DNS_HEADER* requestHeader = (struct DNS_HEADER*) buf;
  printf("Request ID:%x\n", ID);
  uint8_t *ret = malloc(1024 * sizeof(uint8_t));
  // 保存指针的起点
  uint8_t *originRet = ret;
  // 请求类型
  uint16_t queryType;
  uint16_t queryClass;
  uint16_t questionNumber = ntohs(requestHeader->QDCOUNT);
  uint8_t *urlString = malloc(128);
  uint8_t *urlReq = urlString;
  // 设置回复头部
  struct DNS_HEADER* respHeader = (struct DNS_HEADER*)ret;
  setReplyHeader(respHeader, ID);
  uint8_t urlSet[64][64] = {'\0'};
  int urlCnt = 0;
  printf("\nsizeof DNS_HEADER:%ld\n", sizeof(struct DNS_HEADER));
  // 偏移到 question 部
  uint8_t* reqQustion = buf + LEN_DNS_HEADER;
  ret += LEN_DNS_HEADER;

  int url_length = 0;
  // 遍历 url，url 采用字节计数法
  while (1) {
    *ret = *reqQustion;
    uint8_t count = *reqQustion;
    *urlString = (char)(*reqQustion + '0');
    ret++;
    reqQustion++;
    urlString++;
    url_length++;
    if (count == 0) {
      break;
    }
    for (int i = 0; i < count; i++) {
      
      *ret = *reqQustion;
      *urlString = *reqQustion;
      urlSet[urlCnt][i] = *reqQustion;
      ret++;
      urlString++;
      reqQustion++;
      url_length++;
    }
    urlCnt++;
  }
  *urlString = '\0';//这个urlString字符串的最后面会有一个字符0

  // 设置 query Type && query Class

  struct QUERY_ANS *reqQuestionHeader = (struct QUERY_ANS *)reqQustion;
  struct QUERY_ANS *respQuestionHeader = (struct QUERY_ANS *)ret;
  
  // uint16_t* reqQuestionCast = (uint16_t*)reqQustion;
  // uint16_t* retCast = (uint16_t*)ret;
  respQuestionHeader->QUERY_TYPE = reqQuestionHeader->QUERY_TYPE;
  respQuestionHeader->QUERY_CLASS = reqQuestionHeader->QUERY_CLASS;
  printf("query type number:%d\n",ntohs(reqQuestionHeader->QUERY_TYPE));

  reqQustion += sizeof(struct QUERY_ANS);
  ret += sizeof(struct QUERY_ANS);
  
  int ipv4 = 1;
  // Addr. Length
  if(ntohs(reqQuestionHeader->QUERY_TYPE) == QUERY_TYPE_A && checkUrl((char*)urlReq)) {
    // uint16_t *resp_length = (uint16_t *)ret;
    // *resp_length = htons(0x0004);
    // ret += sizeof(uint16_t);
    // // set address
    // uint32_t *ipv4 = (uint32_t *)ret;
    // *ipv4 = htonl(getUrl((char *)urlReq));
    // //ipv4 0.0.0.0，是 block ip，选择不回复
    // if (*ipv4 == 0) {
    //   // respHeader->ANCOUNT = 0;
    //   respHeader->ResponseCode = 3;
    // }
    // ret += sizeof(uint32_t);
    int id = getUrl((char*)urlReq);
    respHeader ->ANCOUNT = htons(ipset[id].num);

    for(int i = 1; i <= ipset[id].num; ++ i) {
      uint16_t offset_ptr_val = 0xc00c;
      uint16_t *offset_ptr = (uint16_t *)ret;
      *offset_ptr = htons(offset_ptr_val);
      ret += sizeof(uint16_t);

      struct QUERY_ANS * question = (struct QUERY_ANS *)(buf + LEN_DNS_HEADER + url_length);
      // Type
      uint16_t* query_type = (uint16_t*)ret;
      *query_type = question->QUERY_TYPE;
      ret+=sizeof(uint16_t);
      // Class
      uint16_t* query_class = (uint16_t*)ret;
      *query_class = question->QUERY_CLASS;
      ret+=sizeof(uint16_t);
      // TTL
      uint32_t *resp_ttl = (uint32_t *)ret;
      *resp_ttl = htonl(TTL);
      ret+=sizeof(uint32_t);

      // RDLENGTH
      uint16_t * rdlength = (uint16_t *)ret;
      *rdlength = htons(0x4);
      ret+=sizeof(uint16_t);

      if(ipset[id].ip[i] == 0) {
        respHeader ->ResponseCode = 3;
      }
      uint32_t * rdata = (uint32_t * )ret;
      *rdata = htonl(ipset[id].ip[i]);
      ret+=sizeof(uint32_t);
    }


  } else {
    if(ntohs(reqQuestionHeader->QUERY_TYPE) != QUERY_TYPE_A)
      ipv4 = 0;
    isRelay = 1;
  }

  printf("request url:%s\n", urlReq);

  // free(urlReq);
  if (isRelay) {
    free(originRet);
    uint8_t * rec = relayDNSPacket(buf, buf);
    if(ipv4 == 1)
      cache_store(rec, (char *)urlReq, url_length);
    free(urlReq);
    return rec;
    // return relayDNSPacket(buf, buf);
  }

  else {
    free(urlReq);
    return originRet;
  }
  
}
