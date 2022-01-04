#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <pcap.h>



#define COUNT_LIMIT 0
#define FILTER_EXP "port 22"

unsigned char pkt[400]={
 0x12,0x34,0x56,0x78,0x9a,0xbc,0x00,0x22,0x48,0x17,0x85,0x1b ,0x08,0x00 ,0x45,0x10
,0x00,0x68 ,0x04,0x55 ,0x40,0x00 ,0x40,0x06 ,0x66,0x4d ,0x0a,0x01 ,0x00,0x05 ,0x70,0xf0
,0x54,0xe8 ,0x00,0x16 ,0xe8,0xa9 ,0xd5,0x2b ,0x9d,0x49 ,0x73,0xcd ,0x35,0x39 ,0x50,0x18
,0x01,0xf5 ,0xd0,0x38 ,0x00,0x00 ,0x6a,0x11 ,0x0e,0x44 ,0xd2,0x7a ,0x59,0x38 ,0x06,0xab
,0x87,0x78 ,0x5f,0x32 ,0x78,0xce ,0x48,0x35 ,0x9e,0x90 ,0x35,0x72 ,0x4d,0x77 ,0x50,0xda
,0x5b,0x19 ,0x7f,0x40 ,0x3e,0xf2 ,0x9e,0x71 ,0xa2,0xfb ,0xb8,0xf6 ,0x50,0x13 ,0x4c,0x5d
,0x14,0x3d ,0x41,0x93 ,0x67,0x77 ,0x67,0xfb ,0x21,0xda ,0xd6,0xfd ,0xa4,0xcb ,0xd3,0xfb
,0xd9,0xab ,0x24,0x7f ,0x62,0xf8,
};

#define MAC_ARG(p) p[0],p[1],p[2],p[3],p[4],p[5]
#define IP_ARG(p) p[0],p[1],p[2],p[3]



int get_device();
void get_device_handler();
int set_filter(char []);
void cap_packet();
void my_packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_packet_info(const u_char *, struct pcap_pkthdr);



int main(int argc, char **argv){
	
	get_device();
	get_device_handler();
	set_filter(FILTER_EXP);
	cap_packet();
	return 0;
}

char *device;
char error_buffer[PCAP_ERRBUF_SIZE];
bpf_u_int32 ip_raw;
bpf_u_int32 subnet_mask_raw;

int get_device(){

	char ip[13];
	char subnet_mask[13];
	int lookup_return_code;
	struct in_addr address;


	device = pcap_lookupdev(error_buffer);
	if(device==NULL){
		printf("Error in finding device: %s\n",error_buffer);
		return 1;
	}
	
	lookup_return_code = pcap_lookupnet(device,&ip_raw,&subnet_mask_raw,error_buffer);

	if(lookup_return_code == -1){
		printf("%d\n",error_buffer);
		return 1;
	}

	address.s_addr = ip_raw;
	strcpy(ip,inet_ntoa(address));
	if(ip == NULL){
		perror("inet_ntoa");
		return 1;
	}

	address.s_addr = subnet_mask_raw;
	strcpy(subnet_mask,inet_ntoa(address));
	if(subnet_mask==NULL){
		perror("inet_ntoa");
		return 1;
	}

	printf("find device: %s, ip: %s, netmask: %s\n",device,ip,subnet_mask);
	return 0;
}

pcap_t *handler;

void get_device_handler(){

	#ifdef MODE_MONITOR

		handler = pcap_create("wlan0",error_buffer);
		pcap_set_rfmon(handler,1);
		pcap_set_promisc(handler,1);
		pcap_set_snaplen(handler,1);
		pcap_set_timeout(handler,1000);
		pcap_activate(handler);
		return;

	#endif
	
	const int packet_count_limit = 1;
	const timeout_limit = 3000; /*milliseconds*/
	
	handler = pcap_open_live(
		device, BUFSIZ,packet_count_limit,timeout_limit,error_buffer
	);
}


int set_filter(char filter_exp[]){

	if(handler ==NULL){
		printf("No handler found\n");
		return 1;
	}

	struct bpf_program filter;
	if(pcap_compile(handler,&filter,filter_exp,0,ip_raw)==-1){
		printf("Error in parse your filter\n");
		return 1;
	}

	if(pcap_setfilter(handler,&filter) == -1){
		printf("Error in setting filter: %s\n",pcap_geterr(handler));
		return 1;
	}

}

void cap_packet(){
	
	pcap_loop(handler,COUNT_LIMIT,my_packet_handler,NULL);
	pcap_close(handler);
}

void my_packet_handler(
	u_char *args, 
	const struct pcap_pkthdr *packet_header,
	const u_char *pcaket_body){
		print_packet_info(pcaket_body,*packet_header);
		return;
}

void print_packet_info(
	const u_char *packet, 
	struct pcap_pkthdr packet_header){


		struct ethhdr *eth_header;

		eth_header = (struct ethhdr *)packet;
		printf("--------------------ETHERNET---------------------\n");
		printf("dst:%02x:%02x:%02x:%02x:%02x:%02x \n",MAC_ARG(eth_header->h_dest));
		printf("src:%02x:%02x:%02x:%02x:%02x:%02x \n",MAC_ARG(eth_header->h_source));
		printf("proto:%04x\n",ntohs(eth_header->h_proto));
		

		struct iphdr *ip_header;

		/*IPv4 proto structure*/
		if(ntohs(eth_header->h_proto)==0x0800){
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
			printf("--------------------IP---------------------\n");
			unsigned char *q = (unsigned char *)&(ip_header->saddr);
			printf("src ip:%d.%d.%d.%d \n",IP_ARG(q));
			q = (unsigned char *)&(ip_header->daddr);
			printf("dst ip:%d.%d.%d.%d \n",IP_ARG(q));
		}


		/*Transmision Control Protlcol structure*/
		if(ip_header->protocol==0x6){
			struct tcphdr *tcp_header = (struct tcphdr *)(packet+sizeof(struct ethhdr)+sizeof(struct iphdr));
			printf("--------------------TCP---------------------\n");
			printf("src port:%d \ndst port:%d \n",ntohs(tcp_header->source),ntohs(tcp_header->dest));
		}

		/*print our packet payload data*/
		int payload_size = packet_header.caplen - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct tcphdr);
		if(payload_size > 0){
			u_char *payload = (u_char *)(packet + (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)));
			const u_char *temp_pointer = payload;
			int byte_count = 0;
			printf("--------------------PAYLOAD---------------------\n");
			while(byte_count++ < payload_size){
				printf("%c",*temp_pointer);
				temp_pointer++;
			}
			printf("\n");
		}
}
