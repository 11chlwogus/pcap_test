all: pcap-test

pcap-test: pcap.c
	gcc -g -o pcap-test pcap.c -lpcap

clean:
	rm -f pcap-test

