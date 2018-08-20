#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <openssl/md5.h>
#include <iostream>
#include <set>

using namespace std;

const char* list;

set<string> s;
set<string>::iterator iter;

//block
static int block(struct nfq_data *tb, struct nfq_q_handle *tqh){
	int id=0;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char* packet;
	int packet_len;
	struct ip *iph;
	struct tcphdr *tcph;
	unsigned char* data;
	unsigned char* target;
	char site[100]={0,};

	ph=nfq_get_msg_packet_hdr(tb);
	if(ph)id=ntohl(ph->packet_id);

	packet_len=nfq_get_payload(tb,&packet);
	iph=(struct ip*)packet;
	tcph=(struct tcphdr*)(packet+4*(iph->ip_hl));
	data=packet+4*(iph->ip_hl)+4*(tcph->th_off);
	
	char *ptr=strtok((char*)data,"\r\n");

	while(ptr!=NULL){
		if(!memcmp(ptr,"Host: ",6)){
			int i=0;
			for(i;ptr[6+i]!='\r';i++){
				site[i]=ptr[6+i];
			}
			site[6+i]='\0';
			
			iter=s.find(site);
			if(iter!=s.end()){
				printf("%s blocked\n",site);
				return nfq_set_verdict(tqh,id,NF_DROP,0,NULL);
			}
			else return nfq_set_verdict(tqh,id,NF_ACCEPT,0,NULL);
		}
		ptr=strtok(NULL,"\r\n");
	}
	return nfq_set_verdict(tqh,id,NF_ACCEPT,0,NULL);
}
 
void make_set_table(){
	FILE *fp=fopen(list,"r");
	char site[100]={0,};
	char tmp;
	int status=0,count=0;

	while(1){
		tmp=fgetc(fp);

		if(tmp==EOF)break;
		if(status==0){
			if(tmp==',')status=1;
			continue;
		}
		else if(status==1){
			if(tmp=='\n'){
				site[count]='\0';
				s.insert(site);
				count=0;status=0;continue;
			}
			site[count]=tmp;count++;
		}
	}
	fclose(fp);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    block(nfa,qh);
	return 1;
}

int main(int argc, char **argv)
{
	if(argc!=2){
		printf("input error\n");
		return 0;
	}
	list=argv[1];
	
	make_set_table();

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
