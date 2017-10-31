all:netfilter_block.c
	g++ -o netfilter_block netfilter_block.c -lnetfilter_queue
