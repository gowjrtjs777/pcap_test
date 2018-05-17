#include <pcap.h>
#include <stdio.h>

int min(int a,int b){
  if(a<b) return a;
  return b;
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  int cnt=0;
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    if(*(packet+23)==17){
      cnt++;
      printf("\n\n*****%d번째 TCP 입니다.*****\n",cnt);
      printf("Ethernet Source MAC Address : (");
      for(int i=6;i<12;i++){
	printf("%02X",*(packet+i));
	if(i!=11)
	  printf(":");
      }
      printf(")\n");
      printf("Ethernet Destination MAC Address : (");
      for(int i=0;i<6;i++){
	printf("%02X",*(packet+i));
	if(i!=5)
	  printf(":");
      }
      printf(")\n");
      printf("Source IP Address : ");
      for(int i=26;i<30;i++){
	printf("%d",*(packet+i));
	if(i!=29)
	  printf(".");
      }
      printf("\n");
      printf("Destination IP Address : ");
      for(int i=30;i<34;i++){
	printf("%d",*(packet+i));
	if(i!=33)
	  printf(".");
      }
      printf("\n");
      printf("TCP's Source Port : %d",256*(*(packet+34))+(*(packet+35)));
      printf("\n");
      printf("TCP's Destination Port : %d",256*(*(packet+36))+(*(packet+37)));
      printf("\n");
      if(header->caplen>54){
        printf("Payload : ");
        for(int i=54;i<min(header->caplen,54+32);i++)
	  printf("%02X ",*(packet+i));
	printf("\n");
      }
    }
  }
  
  pcap_close(handle);
  return 0;
}
