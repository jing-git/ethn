#include <time.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include "proto.h"

/*
nat类型检测
*/

/*
server
*/
static int sock_fullcone_chk;

void natdts_init(int sock_fullcone)
{
	sock_fullcone_chk = sock_fullcone;
}

int natdts_recv(int sock,
                unsigned int ip, unsigned short port,
                unsigned char *buf, int len)
{
	struct nat_detect natdt;
	struct sockaddr_in addr = {0};

	if (len < 2 || buf[0] != NAT_DETECT) {
		return -1;
	}

	natdt.opt = NAT_DETECT;

	memcpy(natdt.wan_ip, &ip, 4);
	memcpy(natdt.wan_port, &port, 2);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip;
	addr.sin_port = port;
	switch (buf[1]) {
	case CHK_SYMMETRIC_REQ_1: {
		natdt.step = CHK_SYMMETRIC_ACK_1;
		printf("CHK_SYMMETRIC_REQ_1\n");
	}
	break;
	case CHK_SYMMETRIC_REQ_2: {
		natdt.step = CHK_SYMMETRIC_ACK_2;
		printf("CHK_SYMMETRIC_REQ_2\n");
	}
	break;
	case CHK_FULLCONE_CLTREQ: {
		natdt.step = CHK_FULLCONE_SRVACK;
		sock = sock_fullcone_chk;
		printf("CHK_FULLCONE_CLTREQ\n");
	}
	break;
	default:
		return -1;
	}

	return sendto(sock,
	              &natdt,
	              sizeof(natdt),
	              0,
	              (const struct sockaddr *)&addr,
	              sizeof(struct sockaddr_in));
}

/*
client

symmetric
	to sip:p1 > get wan_ip1:wan_p1
	to sip:p1+1 > get wan_ip2:wan_p2
	not: wan_ip1==wan_ip2 && wan_p1==wan_p2
	yes: !not
full cone:
	to sip:p1 > recv from sip:p3
*/
#define NAT_MAX_COUNTER	8
#define NAT_CLT_TIMER	2

static int clt_sock;
static int natdtc_step = -1;
static unsigned int wan_ip = 0, sip;
static unsigned short wan_port = 0, sp;
static time_t next_send = 0;
static int send_counter = NAT_MAX_COUNTER;
static int nat_type = NAT_TYPE_UNCHK;

static void natdtc_send(unsigned char step)
{
	struct sockaddr_in a = {0};
	unsigned char buf[2];

	natdtc_step = step;
	next_send = time(NULL) + NAT_CLT_TIMER;
	send_counter--;

	a.sin_family = AF_INET;
	a.sin_addr.s_addr = sip;
	a.sin_port = htons(step == CHK_SYMMETRIC_REQ_2 ? sp + 1 : sp);

	buf[0] = NAT_DETECT;
	buf[1] = step;
	printf("step: %d\n", step);

	sendto(clt_sock,
	       buf,
	       sizeof(buf),
	       0,
	       (const struct sockaddr *)&a,
	       sizeof(struct sockaddr_in));
}

int natdtc_chk(int sock, unsigned int sipn, unsigned short sph)
{
	sip = sipn;
	sp = sph;

	clt_sock = sock;
	send_counter = NAT_MAX_COUNTER;
	nat_type = NAT_TYPE_UNCHK;

	natdtc_send(CHK_SYMMETRIC_REQ_1);

	return 0;
}

int natdtc_recv(unsigned int ip, unsigned short port,
                unsigned char *buf, int len)
{
	struct nat_detect *natdt = (struct nat_detect *)buf;

	if (len < sizeof(struct nat_detect) || buf[0] != NAT_DETECT) {
		return NAT_TYPE_UNCHK;
	}

	switch (natdt->step) {
	case CHK_SYMMETRIC_ACK_1: {
		if (natdtc_step == CHK_SYMMETRIC_REQ_1) {
			memcpy(&wan_ip, natdt->wan_ip, 4);
			memcpy(&wan_port, natdt->wan_port, 2);
			send_counter = NAT_MAX_COUNTER;
			natdtc_send(CHK_SYMMETRIC_REQ_2);
		}
	}
	break;
	case CHK_SYMMETRIC_ACK_2: {
		if (natdtc_step == CHK_SYMMETRIC_REQ_2) {
			if (0 == memcmp(&wan_ip, natdt->wan_ip, 4) &&
			        0 == memcmp(&wan_port, natdt->wan_port, 2)) {
				send_counter = NAT_MAX_COUNTER;
				natdtc_send(CHK_FULLCONE_CLTREQ);
			} else {
				return nat_type = NAT_TYPE_SYMMETRIC;
			}
		}
	}
	break;
	case CHK_FULLCONE_SRVACK: {
		if (natdtc_step == CHK_FULLCONE_CLTREQ) {
			if (ip == sip && port == htons(sp + 2)) {
				return nat_type = NAT_TYPE_FULLCONE;
			}
		}
	}
	break;
	}

	return NAT_TYPE_UNCHK;
}

int natdtc_timer()
{
	if (nat_type != NAT_TYPE_UNCHK) {
		return nat_type;
	}

	if (next_send > time(NULL)) {
		return NAT_TYPE_UNCHK;
	}

	if (send_counter <= 0) {
		switch (natdtc_step) {
		case CHK_SYMMETRIC_REQ_1:
		case CHK_SYMMETRIC_REQ_2://lost pkt
			return nat_type = NAT_TYPE_SYMMETRIC;
		case CHK_FULLCONE_CLTREQ://lost pkt or restric
			return nat_type = NAT_TYPE_RESTRIC;
		}
	}

	switch (natdtc_step) {
	case CHK_SYMMETRIC_REQ_1: {
		natdtc_send(CHK_SYMMETRIC_REQ_1);
	}
	break;
	case CHK_SYMMETRIC_REQ_2: {
		natdtc_send(CHK_SYMMETRIC_REQ_2);
	}
	break;
	case CHK_FULLCONE_CLTREQ: {
		natdtc_send(CHK_FULLCONE_CLTREQ);
	}
	break;
	}

	return NAT_TYPE_UNCHK;
}
