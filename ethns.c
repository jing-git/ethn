#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <getopt.h>
#include <string.h>

#include "proto.h"
#include "misc.h"

struct ethn_host {
	struct ethn_host *next;
	unsigned char ethn_mac[6];
	unsigned char nat_type;
	unsigned int wan_ip;
	unsigned short wan_port;
	unsigned short lan_port;
	time_t last_trans;
};

//nat detect
extern void natdts_init(int sock_fullcone);
extern int natdts_recv(int sock,
                       unsigned int ip, unsigned short port,
                       unsigned char *buf, int len);

/*
main sock / nat check
*/
int sock = -1,
    sock_symmetric_chk = -1,
    sock_fullcone_send = -1;

int ethns_init(char *ip, unsigned short port)
{
	sock = sock_open(ip, port);
	sock_symmetric_chk = sock_open(ip, port + 1);
	sock_fullcone_send = sock_open(ip, port + 2);

	natdts_init(sock_fullcone_send);

	return sock == -1 || sock_symmetric_chk == -1 || sock_fullcone_send == -1 ? -1 : 0;
}

int ethns_clear()
{
	if (sock != -1) {
		close(sock);
	}
	if (sock_symmetric_chk != -1) {
		close(sock_symmetric_chk);
	}
	if (sock_fullcone_send != -1) {
		close(sock_fullcone_send);
	}
}

inline int ethns_send(void *data, int len, struct ethn_host *ethnc)
{
	struct sockaddr_in addr = {0};

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ethnc->wan_ip;
	addr.sin_port = ethnc->wan_port;

	return sendto(sock,
	              data,
	              len,
	              0,
	              (const struct sockaddr *)&addr,
	              sizeof(struct sockaddr_in));
}

/*
半当前所登陆的host写入 /tmp/ethns
每个host的信息保存在文件名为mac的文件中
*/
inline char* nat_type_str(unsigned char natt) {
	static char* type_str[6] = {
		"symmetric",
		"fullcone",
		"restric",
		"unchk",
		"forward",
		"unknown"
	};

	if (natt < NAT_TYPE_SYMMETRIC ||
	        natt > NAT_TYPE_FORWARD) {
		return type_str[5];
	}

	return type_str[natt];
}

void tmp_host_set(unsigned char *mac, struct sockaddr_in *addr, unsigned char nat_type)
{
	char buf[128];
	FILE *fp;

	sprintf(buf, "/tmp/ethns/%02x-%02x-%02x-%02x-%02x-%02x",
	        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	fp = fopen(buf, "w");
	if (fp) {
		fprintf(fp, "%s\n%d\n%s\n",
		        inet_ntoa(addr->sin_addr),
		        ntohs(addr->sin_port),
		        nat_type_str(nat_type));
		fclose(fp);
	}
}

void tmp_host_del(unsigned char *mac)
{
	char buf[128];

	sprintf(buf, "rm /tmp/ethns/%02x-%02x-%02x-%02x-%02x-%02x",
	        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	system(buf);
}

/*
host reg proc
*/
struct ethn_host *host_list;
char reg_key_buf[38];

#define ETHNC_TRANS_TIMEOUT	180
#define ETHNC_CHK_SEC		10

void hosts_init(char *reg_key_str)
{
	host_list = 0;
	strncpy(reg_key_buf, reg_key_str, 31);
}

void hosts_clear()
{
	struct ethn_host *h, *n;

	for (h = host_list; h; ) {
		n = h->next;
		free(h);
		h = n;
	}
	host_list = 0;
}

inline struct ethn_host *host_find_by_mac(unsigned char *ethn_mac)
{
	struct ethn_host *h;

	for (h = host_list; h; ) {
		if (0 == memcmp(ethn_mac, h->ethn_mac, 6)) {
			//X > C
			h->last_trans = time(NULL);
			break;
		}
		h = h->next;
	}

	return h;
}

void host_update(unsigned char *mac, unsigned char code)
{
	struct ethn_host *h;
	struct ethn_clt_update clt_upd;

	clt_upd.opt = CLT_UPDATE;
	clt_upd.code = code;
	memcpy(clt_upd.ethn_mac, mac, 6);

	for (h = host_list; h; h = h->next) {
		if (memcmp(h->ethn_mac, mac, 6) != 0) {
			ethns_send(&clt_upd, sizeof(struct ethn_clt_update), h);
		}
	}
}

struct ethn_host *host_register(unsigned char *ethn_mac,
                                struct sockaddr_in *addr,
                                char *md5_key,
                                unsigned char nat_type,
                                unsigned short lan_port)
{
	char log_buf[64];
	unsigned char md5_val[16];
	struct ethn_host *h;
	int new_one;

	//chk md5_key
	md5_key_mac_enc(reg_key_buf, ethn_mac, md5_val);
	if (memcmp(md5_key, md5_val, 16)) {
		//err md5
		sprintf(log_buf,
		        "! %02x:%02x:%02x:%02x:%02x:%02x %s %d",
		        ethn_mac[0], ethn_mac[1], ethn_mac[2],
		        ethn_mac[3], ethn_mac[4], ethn_mac[5],
		        inet_ntoa(addr->sin_addr),
		        ntohs(addr->sin_port));
		log_line(log_buf);
		printf("%s\n", log_buf);

		return 0;
	}

	h = host_find_by_mac(ethn_mac);
	//new mac
	if (h == 0) {
		new_one = 1;
		h = (struct ethn_host *)malloc(sizeof(struct ethn_host));
		if (h) {
			h->next = host_list;
			host_list = h;
			memcpy(h->ethn_mac, ethn_mac, 6);
			h->last_trans = time(0);
		} else {
			return 0;
		}
	} else {
		new_one = 0;
	}

	//new wan
	if (h->wan_ip != addr->sin_addr.s_addr ||
	        h->wan_port != addr->sin_port) {
		sprintf(log_buf,
		        "+%d %02x:%02x:%02x:%02x:%02x:%02x %s %d %d",
		        new_one,
		        h->ethn_mac[0], h->ethn_mac[1], h->ethn_mac[2],
		        h->ethn_mac[3], h->ethn_mac[4], h->ethn_mac[5],
		        inet_ntoa(addr->sin_addr),
		        ntohs(addr->sin_port),
		        nat_type);
		log_line(log_buf);
		printf("%s\n", log_buf);

		tmp_host_set(h->ethn_mac, addr, nat_type);

		if (h->wan_ip != 0 ) {
			/*
			let others known the host updated
			the pkt may lost
			*/
			host_update(ethn_mac, CLT_UPD_INFO);
		}
	}
	//new nat type
	if (h->nat_type != nat_type) {
		tmp_host_set(h->ethn_mac, addr, nat_type);
	}

	//set wan info
	h->wan_ip = addr->sin_addr.s_addr;
	h->wan_port = addr->sin_port;
	h->nat_type = nat_type;
	h->lan_port = lan_port;

	return h;
}

void host_timer()
{
	char log_buf[64];
	struct ethn_host *h, *n, *b;
	time_t now;
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;

	b = 0;
	now = time(NULL);
	for (h = host_list; h; ) {
		n = h->next;
		//no one trans with it in ETHNC_TRANS_TIMEOUT secs
		if (h->last_trans + ETHNC_TRANS_TIMEOUT < now) {
			//try log
			addr.sin_addr.s_addr = h->wan_ip;
			addr.sin_port = h->wan_port;
			sprintf(log_buf,
			        "- %02x:%02x:%02x:%02x:%02x:%02x %s %d",
			        h->ethn_mac[0], h->ethn_mac[1], h->ethn_mac[2],
			        h->ethn_mac[3], h->ethn_mac[4], h->ethn_mac[5],
			        inet_ntoa(addr.sin_addr),
			        ntohs(addr.sin_port));
			log_line(log_buf);
			printf("%s\n", log_buf);

			tmp_host_del(h->ethn_mac);

			free(h);

			if (b) {
				b->next = n;
			} else {
				host_list = n;
			}
		} else {
			b = h;
		}
		h = n;
	}
}

/*
ethn server处理例程

1，host登陆注册
2，中转数据
3，检测nat类型
4，获取某个host的信息
*/
void ethns_loop()
{
	unsigned char MAC_1[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	unsigned char pkt_buf[3044];
	struct sockaddr_in recv_addr, addr;
	struct ethn_host *host;
	int recv_len, recv_addr_len;

	time_t next_chk = time(0) + ETHNC_CHK_SEC;

	struct ethn_reg_req *reg_hdr = (struct ethn_reg_req *)pkt_buf;
	struct ethn_reg_ack *reg_ack_hdr = (struct ethn_reg_ack *)pkt_buf;
	struct ethn_data *data_hdr = (struct ethn_data *)pkt_buf;
	struct ethn_cltinfo *cltinfo = (struct ethn_cltinfo *)pkt_buf;

	unsigned char *reg_ack_md5 = pkt_buf + 1024;

	struct timeval select_time;
	int sock_fd, max_sock_fd;
	fd_set sock_fd_set;

	max_sock_fd = (sock > sock_symmetric_chk ? sock : sock_symmetric_chk);
	max_sock_fd++;

	while (1) {
		select_time.tv_sec = 1;
		select_time.tv_usec = 0;
		FD_ZERO(&sock_fd_set);
		FD_SET(sock, &sock_fd_set);
		FD_SET(sock_symmetric_chk, &sock_fd_set);
		sock_fd = select(max_sock_fd, &sock_fd_set, NULL, NULL, &select_time);

		if (sock_fd > 0) {
			sock_fd = FD_ISSET(sock, &sock_fd_set) ? sock : sock_symmetric_chk;
			recv_addr_len = sizeof(struct sockaddr_in);
			recv_len = recvfrom(sock_fd,
			                    pkt_buf,
			                    3044,
			                    0,
			                    (struct sockaddr *)&recv_addr,
			                    (socklen_t *)&recv_addr_len);

			if (recv_len > 0) {
				if (pkt_buf[0] == REG_REQ) { //clt req reg
					if (recv_len >= sizeof(struct ethn_reg_req)) {
						host = host_register(reg_hdr->ethn_mac,
						                     &recv_addr,
						                     reg_hdr->md5_key,
						                     reg_hdr->nat_type,
						                     *(unsigned short*)reg_hdr->lan_port);
						if (host) {
							reg_ack_hdr->opt = REG_ACK;
							memcpy(reg_ack_hdr->wan_ip, &host->wan_ip, 4);
							memcpy(reg_ack_hdr->wan_port, &host->wan_port, 2);
							//md5:ip+port
							memcpy(reg_ack_md5, &reg_ack_hdr->wan_ip, 4);
							memcpy(reg_ack_md5 + 4, &reg_ack_hdr->wan_port, 2);
							md5_key_mac_enc(reg_key_buf, reg_ack_md5, reg_ack_hdr->md5_key);
							ethns_send(pkt_buf, sizeof(struct ethn_reg_ack), host);
						}
					}
				} else if (pkt_buf[0] == DATA_TRANS) { //clt trans data
					if (recv_len >= sizeof(struct ethn_data)) {
						host = host_find_by_mac(data_hdr->dst_mac);
						if (host) { //unicasthost
							ethns_send(pkt_buf, recv_len, host);
						} else if (0 == memcmp(MAC_1, data_hdr->dst_mac, 6)) { //broadcast
							for (host = host_list; host; host = host->next) {
								if (host->wan_ip == recv_addr.sin_addr.s_addr &&
								        host->wan_port == recv_addr.sin_port) {
									continue;
								}
								ethns_send(pkt_buf, recv_len, host);
							}
						}
					}
				}  else if (pkt_buf[0] == NAT_DETECT) { //clt detects themselives' nat type
					natdts_recv(sock_fd,
					            recv_addr.sin_addr.s_addr,
					            recv_addr.sin_port,
					            pkt_buf,
					            recv_len);
				} else if (pkt_buf[0] == GET_CLT) { //clt gets other's info
					if (recv_len >= sizeof(struct ethn_data)) {
						for (host = host_list;
						        host && memcmp(host->ethn_mac, data_hdr->dst_mac, 6);
						        host = host->next) {
						}

						cltinfo->opt = GET_CLT_ACK;
						memcpy(pkt_buf + 256, data_hdr->dst_mac, 6);
						memcpy(cltinfo->ethn_mac, pkt_buf + 256, 6);
						if (host) {
							cltinfo->code = 0;
							cltinfo->nat_type = host->nat_type;
							memcpy(cltinfo->wan_ip, &host->wan_ip, 4);
							memcpy(cltinfo->wan_port, &host->wan_port, 2);
							memcpy(cltinfo->lan_port, &host->lan_port, 2);
						} else {
							cltinfo->code = -1;
						}

						sendto(sock_fd,
						       pkt_buf,
						       sizeof(struct ethn_cltinfo),
						       0,
						       (struct sockaddr *)&recv_addr,
						       sizeof(struct sockaddr_in));
					}
				}
			} else {
			}
		} else {
		}

		if (next_chk < time(0)) {
			next_chk = time(0) + ETHNC_CHK_SEC;
			host_timer();
		}
	}
}

int main(int argc, char *const argv[])
{
	char ip_str[16], port_str[8], key_str[32];
	int ch;
	struct option long_opt[] = {
		{"ip", required_argument, 0, 'a'},
		{"port", required_argument, 0, 'b'},
		{"key",	required_argument, 0, 'c'},
		{"log",	required_argument, 0, 'd'},
		{0, 0, 0, 0}
	};

	//默认运行参数
	strcpy(ip_str, "0.0.0.0");
	strcpy(port_str, "35811");
	strcpy(key_str, "helloworld");

	while (-1 != (ch = getopt_long_only(argc, argv, "abcd:", long_opt, 0))) {
		switch (ch) {
		case 'a': {
			strncpy(ip_str, optarg, 15);
		}
		break;
		case 'b': {
			strncpy(port_str, optarg, 7);
		}
		break;
		case 'c': {
			strncpy(key_str, optarg, 31);
		}
		break;
		case 'd': {
			log_init(optarg);
		}
		break;
		}
	}

	ch = atoi(port_str);
	if (ethns_init(ip_str, ch)) {
		printf("ethns_init err : %d\n", errno);
		return -1;
	}

	hosts_init(key_str);

	system("rm -rf /tmp/ethns");
	system("mkdir /tmp/ethns");
	printf("ethns running..\n");
	ethns_loop();
	printf("ethns stop.\n");

	ethns_clear();
	hosts_clear();
	log_clear();

	return 0;
}
