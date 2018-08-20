all:netfilter

netfilter:netfilter.o
	g++ -std=c++14 -o netfilter_test netfilter_test.o -lnetfilter_queue -lssl -lcrypto

netfilter.o:
	g++ -std=c++14 -c -o netfilter_test.o netfilter_test.c -lnetfilter_queue -lssl -lcrypto

clean:
	rm -f *.o
	rm -f netfilter_test
	
