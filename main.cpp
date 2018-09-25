#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <string.h>
struct ethernet{
  uint8_t des_ars[ETHER_ADDR_LEN];
  uint8_t src_ars[ETHER_ADDR_LEN];
  uint16_t type;
};

struct ip{
  uint8_t head_len:4, version:4;
  uint8_t tos;
  uint16_t tot_pac_len;
  uint16_t id;
  uint16_t off;
  uint8_t ttl;
  uint8_t prtc_id;
  uint16_t sum;
  uint32_t src;
  uint32_t des;
};

struct tcp{
  uint16_t src_port;
  uint16_t des_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t reserved:4, offset:4;
  uint8_t flags;
  uint16_t win;
  uint16_t sum;
  uint16_t urp;
};

void print_mac_ars(uint8_t * ars,char * str){
  printf("%s : ",str);
  for(int i=0;i<ETHER_ADDR_LEN;i++){
    if(i!=0) printf(":");
    printf("%02X",(uint8_t)*(ars+i));
  }
  printf("\n");
}

void print_ip_ars(uint32_t ars,char * str){
  printf("%s : ",str);
  for(int i=0;i<sizeof(ars);i++){
    if(i!=0) printf(".");
    printf("%d",(ars>>(8*(sizeof(ars)-i-1)))&0xff);
  }
  printf("\n");
}

void print_port_ars(uint16_t ars,char * str){
  printf("%s : %d\n",str,ars);
}

void print_data(uint8_t * ars, uint32_t len){
  printf("data : ");
  if(len<32){
    for(int i=0;i<len;i++)
      printf("%02X ", (uint8_t)*(ars+i));
  }
  else{
    for(int i=0;i<32;i++)
      printf("%02X ", (uint8_t)*(ars+i));
  }
}

void print(uint8_t * pac){
  struct ethernet * e_ptr;
  // e_ptr = (struct ethernet*)malloc(sizeof(struct ethernet));
  e_ptr =(struct ethernet *) pac;
  print_mac_ars(e_ptr->src_ars,"source of MAC-address");
  print_mac_ars(e_ptr->des_ars,"destination of MAC-address");
  if(ntohs(e_ptr->type)!=ETHERTYPE_IP){
    printf("This is not ipv4\n");
    return;
  }
  //free(e_ptr);
  
  struct ip * i_ptr;
  //i_ptr = (struct ip*)malloc(sizeof(struct ip));
  i_ptr = (struct ip*)(pac+sizeof(struct ethernet));
  print_ip_ars(ntohl(i_ptr->src),"source IP-address");
  print_ip_ars(ntohl(i_ptr->des),"destination IP-address");
  uint32_t ip_hlen = (i_ptr->head_len) * 4;
  uint32_t ip_tlen = ntohs (i_ptr->tot_pac_len);
  if((i_ptr->prtc_id)!=IPPROTO_TCP){
    printf("This is not TCP\n");
    return;
  }
  //free(i_ptr);

  struct tcp * t_ptr;
  //t_ptr = (struct tcp*)malloc(sizeof(struct tcp));
  t_ptr = (struct tcp*)(pac+sizeof(struct ethernet)+ip_hlen);
  print_port_ars(ntohs(t_ptr->src_port),"source port");
  print_port_ars(ntohs(t_ptr->des_port),"destination port");
  uint32_t tcp_hlen = (t_ptr->offset) * 4;
  uint32_t data_len = ip_tlen - ip_hlen - tcp_hlen;
  if(data_len>0)
    print_data(pac+sizeof(struct ethernet)+ip_hlen+tcp_hlen,data_len);
  else
    printf("no data");
  //free(t_ptr);
  printf("\n"); 
}

void usage(){
  printf("syntax : pcap_test <interface>\n");
  printf("sample : pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  //pcap_t* handle = pcap_open_offline(argv[1],errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("==============================\n");
    printf("We captured %u bytes\n",header->caplen);
    print((uint8_t *) packet);
    printf("\n");
  }
  pcap_close(handle);
  return 0;
}
