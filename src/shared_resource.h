#include <stdint.h>
#include <pthread.h>
struct INTERCEPTOR_TABLE {
  uint32_t ipv4;
  char* domainName;
};

struct INTERCEPTOR_TABLE *getUrlTable() ;

pthread_mutex_t* getRWLock();

uint8_t *getIdTable();

void initSharedResource();

uint8_t checkUrl(char *url);

int getUrl(char *url);

char *getBlockList();

char *getRelayServerIP();
