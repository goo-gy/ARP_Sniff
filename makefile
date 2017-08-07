arp_sniff: fun.o arp_sniff.o
	gcc -W -Wall -o arp_sniff arp_sniff.o fun.o -lpcap
arp_sniff.o: arp_sniff.c header.h
	gcc -W -Wall -g -c arp_sniff.c
fun.o: fun.c header.h
	gcc -W -Wall -g -c fun.c
clear:
	rm fun.o arp_sniff.o arp_sniff
