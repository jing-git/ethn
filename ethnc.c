#include <time.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "tap.h"
#include "misc.h"
#include "proto.h"
#include "twofish.h"

struct ethn_host {
    struct ethn_host *next;
    unsigned int peer_ip;       //用于与host通信的对端ip
    unsigned int wan_ip;        //reg后，ethns看到的ip
    unsigned int *lan_ips;      /*lan接口上各ip的广播地址（不包括tap）
                                  非空：正在尝试lan发现
                                  空：lan发现已结束
                                */
    unsigned short peer_port;
    unsigned short wan_port;
    unsigned short lan_port;
    unsigned char ethn_mac[6];  //标识host的mac地址
    unsigned char wan_cnt;      //get_clt/try_punch的次数
    unsigned char lan_cnt;      //当前lan_ips[idx]尝试发现的次数
    unsigned char lan_idx;      //正在使用lan_ips[idx]尝试lan发现
    unsigned char nat_type;
    time_t last_trans;          //最后一次接收到host数据的时间
    unsigned char status;
};

/**/
extern int natdtc_chk(int sock,
                      unsigned int sipn,
                      unsigned short sph);
extern int natdtc_recv(unsigned int ip,
                       unsigned short port,
                       unsigned char *buf,
                       int len);
extern int natdtc_timer();

/**/
struct ethn_tap tap = {0};
unsigned char md5_key[16], server_key[32];
struct sockaddr_in server_addr;
TWOFISH *tf_enc, *tf_dec;
int sleep_from_m, sleep_to_m;
unsigned int wan_ip;
unsigned short wan_port;
char server_host[64];
unsigned char mode_forward;
unsigned short lan_port;
unsigned int ethnc_ip_broadcast;

/*
wan通信
*/
//get server ip by server_host
int server_ip_get()
{
    char **pp;
    struct hostent *he = gethostbyname(server_host);

    server_addr.sin_family = 0;
    server_addr.sin_addr.s_addr = 0;
    if (he) {
        server_addr.sin_family = he->h_addrtype;
        for (pp = he->h_addr_list; *pp != NULL; pp++) {
            memcpy(&server_addr.sin_addr.s_addr, *pp, he->h_length);
        }

        return 0;
    }

    return errno;
}

int wan_sock = -1;
unsigned char nat_type = NAT_TYPE_UNCHK;

int local_port_get() {
    struct sockaddr_in addr;
    int addr_len = sizeof(struct sockaddr_in);

    if (getsockname(wan_sock, (struct sockaddr*)&addr, &addr_len) == 0) {
        lan_port = addr.sin_port;

        return lan_port;
    }

    return -1;
}

void peer_cls();

int wan_reset()
{
    //close
    if (wan_sock != -1) {
        close(wan_sock);
        wan_sock = -1;
        peer_cls();
    }

    server_ip_get();

    nat_type = (mode_forward == 0 ? NAT_TYPE_UNCHK : NAT_TYPE_FORWARD);
    wan_sock = sock_open("0.0.0.0", 0);
    local_port_get();

    return wan_sock != -1;
}

/*
wan/lan p2p
wan
lan
*/
#define HOST_PUNCH_MAX      8
#define HOST_GET_MAX        4
#define HOST_PUNCH_LAN_MAX  3

#define UDP_TIMEOUT         55

enum HOST_ST {
    HOST_ST_INIT = 0,
    HOST_ST_GETING,
    HOST_ST_WAN_PUNCHING,
    HOST_ST_TRANSING
};

unsigned int * get_broadcast() {//获取本地所有的广播地址，用于lan的发现
    FILE *pipe;
    char buf[256], *p, *q;
    unsigned int *ips, n, brd;

    ips = NULL;
    pipe = popen("ip addr | grep inet", "r");
    if (pipe != NULL) {
        n = 0;
        ips = (unsigned int *)malloc(sizeof(unsigned int));
        while (fgets(buf, sizeof(buf), pipe) != NULL) {
            p = strstr(buf, " brd ");
            if (p) {
                p += 5;
                q = strchr(p, ' ');
                if (q) {
                    *q = '\0';
                    brd = inet_addr(p);
                    if (brd != ethnc_ip_broadcast) { //过滤掉tap口
                        ips = (unsigned int *)realloc(ips, sizeof(unsigned int) * (n + 1));
                        ips[n] = brd;
                        n++;
                    }
                }
            }
        }
        //end with 0
        ips[n] = 0;
        pclose(pipe);
    }

    return ips;
}

struct ethn_host *peers = 0;

void peer_cls() {
    struct ethn_host *h, *n;

    for (h = peers; h; h = n) {
        n = h->next;
        if (h->lan_ips) {
            free(h->lan_ips);
        }
        free(h);
    }

    peers = 0;
}

inline struct ethn_host* get_peer(unsigned char *dst_mac)
{
    struct ethn_host *peer;

    for (peer = peers;
            peer && memcmp(peer->ethn_mac, dst_mac, 6);
            peer = peer->next) {
    }

    return peer;
}

inline void set_peer_addr(struct ethn_host *h, struct sockaddr_in *addr) {
    h->peer_ip = addr->sin_addr.s_addr;
    h->peer_port = addr->sin_port;
    h->status = HOST_ST_TRANSING;
}

inline void discv_over(struct ethn_host *h) {
    if (h->lan_ips) {
        free(h->lan_ips);
        h->lan_ips = 0;
    }
}

struct ethn_host* get_alloc_peer(unsigned char *dst_mac)
{
    struct ethn_host *peer;

    peer = get_peer(dst_mac);

    if (peer == 0) {
        peer = (struct ethn_host *)malloc(sizeof(struct ethn_host));
        if (peer) {
            peer->next = peers;
            peers = peer;

            peer->peer_ip = 0;
            peer->wan_ip = 0;
            peer->lan_ips = 0;
            peer->peer_port = 0;
            peer->wan_port = 0;
            peer->lan_port = 0;

            memcpy(peer->ethn_mac, dst_mac, 6);

            peer->wan_cnt = 0;
            peer->lan_cnt = 0;
            peer->lan_idx = 0;

            peer->nat_type = NAT_TYPE_UNCHK;

            peer->last_trans = time(0);

            peer->status = HOST_ST_INIT;
        }
    }

    return peer;
}

void peer_punch_discv(struct ethn_host *h, int punch) {
    struct ethn_data punch_req = {0};
    struct sockaddr_in addr = {0};

    if (punch) {
        h->wan_cnt++;
        if (h->wan_cnt > HOST_PUNCH_MAX) {//punch fail, ethns forward
            set_peer_addr(h, &server_addr);
            return ;
        }
        punch_req.opt = WAN_PUNCH;
        memcpy(&addr.sin_addr.s_addr, &h->wan_ip, 4);
        memcpy(&addr.sin_port, &h->wan_port, 2);

        printf("punch.\n");
    } else {
        if (!h->lan_ips) {
            return ;
        }

        punch_req.opt = LAN_DISCV;

        h->lan_cnt ++;
        if (h->lan_cnt > HOST_PUNCH_LAN_MAX) {//try next broadcast ip
            h->lan_cnt = 0;
            h->lan_idx ++;
        }

        if (h->lan_ips[h->lan_idx] == 0) {//no more broadcast ip
            discv_over(h);
            return ;
        }

        memcpy(&addr.sin_addr.s_addr, &h->lan_ips[h->lan_idx], 4);
        memcpy(&addr.sin_port, &h->lan_port, 2);

        printf("discv.\n");
    }
    memcpy(punch_req.dst_mac, tap.mac, 6);
    addr.sin_family = AF_INET;

    sendto(wan_sock,
           &punch_req,
           sizeof(struct ethn_data),
           0,
           (struct sockaddr *)&addr,
           sizeof(struct sockaddr_in));
}

void wan_punch_proc(unsigned char *pkt, int pkt_len, struct sockaddr_in *addr)
{
    struct ethn_host *h;
    struct ethn_data *punch_pkt = (struct ethn_data *)pkt;

    if (pkt_len < sizeof(struct ethn_data)) {
        return ;
    }

    if (punch_pkt->opt == WAN_PUNCH) {//recv punch req
        if (nat_type != NAT_TYPE_FORWARD) {
            h = get_alloc_peer(punch_pkt->dst_mac);
            if (h) {
                if (h->status == HOST_ST_INIT ||
                        h->status == HOST_ST_WAN_PUNCHING) {
                    set_peer_addr(h, addr);
                }
                //ack
                punch_pkt->opt = WAN_PUNCH_ACK;
                memcpy(punch_pkt->dst_mac, tap.mac, 6);
                sendto(wan_sock,
                       punch_pkt,
                       sizeof(struct ethn_data),
                       0,
                       (struct sockaddr *)addr,
                       sizeof(struct sockaddr_in));
            }
        }
    } else if (punch_pkt->opt == WAN_PUNCH_ACK) {//recv punch ack
        h = get_peer(punch_pkt->dst_mac);
        if (h) {
            if (h->status == HOST_ST_WAN_PUNCHING) {
                set_peer_addr(h, addr);
            }
        }
    }
}

void discv_proc(unsigned char *pkt, int pkt_len, struct sockaddr_in *addr) {
    struct ethn_host *h;
    struct ethn_data *discv_pkt = (struct ethn_data *)pkt;

    if (pkt_len < sizeof(struct ethn_data)) {
        return ;
    }

    if (discv_pkt->opt == LAN_DISCV) {
        h = get_alloc_peer(discv_pkt->dst_mac);
        if (h && h->lan_ips) {
            set_peer_addr(h, addr);
            discv_over(h);

            discv_pkt->opt = LAN_DISCV_ACK;
            memcpy(discv_pkt->dst_mac, tap.mac, 6);
            sendto(wan_sock,
                   discv_pkt,
                   sizeof(struct ethn_data),
                   0,
                   (struct sockaddr *)addr,
                   sizeof(struct sockaddr_in));

            printf("discv: %02x-%02x-%02x-%02x-%02x-%02x %s %d\n",
                   discv_pkt->dst_mac[0], discv_pkt->dst_mac[1], discv_pkt->dst_mac[2],
                   discv_pkt->dst_mac[3], discv_pkt->dst_mac[4], discv_pkt->dst_mac[5],
                   inet_ntoa(*(struct in_addr*)&addr->sin_addr.s_addr),
                   ntohs(addr->sin_port));
        }
    } else if (discv_pkt->opt == LAN_DISCV_ACK) {
        h = get_peer(discv_pkt->dst_mac);
        if (h && h->lan_ips) {
            set_peer_addr(h, addr);
            discv_over(h);

            printf("discv ack: %s %d\n",
                   inet_ntoa(*(struct in_addr*)&addr->sin_addr.s_addr),
                   ntohs(addr->sin_port));
        }
    }
}

void get_wanaddr_proc(unsigned char *pkt, int pkt_len)
{
    struct ethn_host *h;
    struct ethn_cltinfo *cltinfo = (struct ethn_cltinfo *)pkt;

    /*
    -1: srv can't find the cltinfo->ethn_mac in reg list
    0 : srv ack the cltinfo
    find and proc
    */
    if (cltinfo->opt == GET_CLT_ACK &&
            (pkt_len >= sizeof(struct ethn_cltinfo) ||
             (pkt_len >= 2 && cltinfo->code == 0xff))) {

        h = get_peer(cltinfo->ethn_mac);
        if (h) {
            h->last_trans = time(0);

            if (cltinfo->code == 0xff) {//clt not exist
                h->status = HOST_ST_TRANSING;
                set_peer_addr(h, &server_addr);
            } else {
                memcpy(&h->wan_ip, cltinfo->wan_ip, 4);
                memcpy(&h->wan_port, cltinfo->wan_port, 2);
                memcpy(&h->lan_port, cltinfo->lan_port, 2);
                h->nat_type = cltinfo->nat_type;
                h->lan_ips = get_broadcast();

                if (h->nat_type == NAT_TYPE_SYMMETRIC ||
                        nat_type == NAT_TYPE_FORWARD) {
                    set_peer_addr(h, &server_addr);
                    //discv
                    peer_punch_discv(h, 0);
                    return ;
                }
                //try punching
                h->status = HOST_ST_WAN_PUNCHING;
                h->wan_cnt = 0;
                peer_punch_discv(h, 1);
                //discv
                peer_punch_discv(h, 0);
            }
        }
    }
}

void get_wanaddr(struct ethn_host *h) {
    struct ethn_data wanaddr_req = {0};

    h->wan_cnt ++;
    if (h->wan_cnt > HOST_GET_MAX) {
        set_peer_addr(h, &server_addr);
        return ;
    }

    h->status = HOST_ST_GETING;

    wanaddr_req.opt = GET_CLT;
    memcpy(wanaddr_req.dst_mac, h->ethn_mac, 6);
    sendto(wan_sock,
           &wanaddr_req,
           sizeof(struct ethn_data),
           0,
           (struct sockaddr *)&server_addr,
           sizeof(struct sockaddr_in));
}

struct sockaddr *get_peer_addr(unsigned char *mac)
{
    static struct sockaddr_in addr = {0};
    struct ethn_host *h;

    //group/broadcast mac addr，如果对方此时的p2p_wan没有超时，那么要等到UDP_TIMEOUT后才有响应
    if (mac[0] & 0x01) {
        return (struct sockaddr *)&server_addr;
    }

    h = get_alloc_peer(mac);
    if (h) {
        if (h->status == HOST_ST_TRANSING) {//transing
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = h->peer_ip;
            addr.sin_port = h->peer_port;

            return (struct sockaddr *)&addr;
        } else if (h->status == HOST_ST_INIT) {//init
            get_wanaddr(h);
        }
    }

    return (struct sockaddr *)&server_addr;
}

inline void peer_upadte(unsigned char *mac, unsigned int ip, unsigned short port) {
    struct ethn_host *h;

    h = get_peer(mac);
    if (h) {
        if (h->status == HOST_ST_TRANSING) {
            if (ip != server_addr.sin_addr.s_addr) {
                h->wan_ip = ip;
                h->wan_port = port;
            }
        }
        h->last_trans = time(NULL);
    }
}

void peer_timer()
{
    static time_t next_chk = 0;
    time_t now = time(0);
    struct ethn_host *h, *b, *n;

    if (next_chk > now) {
        return ;
    } else {
        next_chk = now + 3;
    }

    for (b = 0, h = peers; h; h = n) {
        n = h->next;
        if (h->status == HOST_ST_TRANSING) {
            if (now - h->last_trans > UDP_TIMEOUT) {//timeout
                if (b) {
                    b->next = n;
                } else {
                    peers = n;
                }
                discv_over(h);
                free(h);
            } else {
                b = h;
                if (h->lan_ips) {//lan discv
                    peer_punch_discv(h, 0);
                }
            }
        } else if (h->status == HOST_ST_WAN_PUNCHING) {
            peer_punch_discv(h, 1);
            peer_punch_discv(h, 0);
        } else if (h->status == HOST_ST_GETING) {
            get_wanaddr(h);
        }
    }
}

void clt_updated_proc(struct ethn_clt_update *clt_upd) {
    struct ethn_host *h, *b, *n;

    for (b = 0, h = peers; h; h = n) {
        n = h->next;
        if (memcmp(h->ethn_mac, clt_upd->ethn_mac, 6) == 0) { //del & free host
            if (b != 0) {
                b->next = n;
            } else {
                peers = n;
            }
            discv_over(h);
            free(h);

            return ;
        }
    }
}

/*
登陆至ethns服务器
维护登陆的状态
*/
enum ETHNC_STATE {
    ETHNC_UNKOWN,
    ETHNC_REG,
    ETHNC_TRANS,
    ETHNC_KEEPALIVE
};

#define REG_TICK_MIN    1
#define REG_TICK_MAX    5
#define REG_TRY_MAX     8

int status = ETHNC_UNKOWN;
time_t reg_next = 0, server_last_trans;
int reg_next_tick = REG_TICK_MIN;
int reg_try_count = 0;

void ethnc_reg_try(struct ethn_reg_req *reg_hdr)
{
    if (reg_next < time(0)) { //time to reg
        if (++reg_try_count > REG_TRY_MAX) { //to much fail, reset the sock, and try reg
            wan_reset();
            reg_try_count = 0;
            reg_next_tick = REG_TICK_MIN;
            status = ETHNC_REG;
        }

        reg_next = time(0) + reg_next_tick;
        if (reg_next_tick < REG_TICK_MAX) { //try reg timeout: 1,2,3,4,5,5..
            reg_next_tick++;
        }

        reg_hdr->opt = REG_REQ;
        reg_hdr->nat_type = nat_type;
        memcpy(reg_hdr->ethn_mac, tap.mac, 6);
        memcpy(reg_hdr->lan_port, &lan_port, 2);
        memcpy(reg_hdr->md5_key, md5_key, 16);

        sendto(wan_sock,
               reg_hdr,
               sizeof(struct ethn_reg_req),
               0,
               (struct sockaddr *)&server_addr,
               sizeof(struct sockaddr_in));

        printf("try reg..\n");
    }
}

void ethnc_reg_proc(struct ethn_reg_ack *ack)
{
    unsigned char md5_val[16], md5_buf[6];
    struct sockaddr_in addr;

    memcpy(md5_buf, ack->wan_ip, 4);
    memcpy(md5_buf + 4, ack->wan_port, 2);
    md5_key_mac_enc(server_key, md5_buf, md5_val);
    if (memcmp(ack->md5_key, md5_val, 16)) { //wrong md5 val
        return ;
    }

    memcpy(&wan_ip, ack->wan_ip, 4);
    memcpy(&wan_port, ack->wan_port, 2);

    server_last_trans = time(0);
    reg_next_tick = REG_TICK_MIN;
    reg_try_count = 0;

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_addr.s_addr = wan_ip;
    addr.sin_port = wan_port;

    if (status == ETHNC_REG) { //after reg, try to check nat type
        natdtc_chk(wan_sock, server_addr.sin_addr.s_addr, ntohs(server_addr.sin_port));
    }

    status = ETHNC_TRANS;

    printf("reg ok: %s:%d\n",
           inet_ntoa(addr.sin_addr),
           ntohs(addr.sin_port));
}

/*
udp/tap io
定时器
*/
void ethnc_loop()
{
    //(2+6+14+1500)*2
    uint8_t pkt_buf[3044], tf_buf[3044];
    int sock_fd, max_sock_fd;
    fd_set sock_fd_set;
    struct timeval select_time;
    ssize_t recv_len;
    struct sockaddr_in recv_addr;
    socklen_t recv_addr_len;
    time_t now, sleep_chk, last_sec;
    struct tm *tm_p;
    int now_m;

    struct ethn_reg_req *reg_hdr = (struct ethn_reg_req *)pkt_buf;
    struct ethn_reg_ack *reg_ack_hdr = (struct ethn_reg_ack *)pkt_buf;
    struct ethn_data *data_hdr = (struct ethn_data *)pkt_buf;
    struct ethn_data *data_hdr_tf = (struct ethn_data *)tf_buf;

    //max sock
    max_sock_fd = (tap.fd > wan_sock ? tap.fd : wan_sock);
    max_sock_fd++;
    //try reging
    status = ETHNC_REG;
    ethnc_reg_try(reg_hdr);

    last_sec = 0;
    while (1) {
        recv_addr_len = sizeof(struct sockaddr_in);
        //wait / sock fd set
        select_time.tv_sec = 1;
        select_time.tv_usec = 0;
        FD_ZERO(&sock_fd_set);
        FD_SET(wan_sock, &sock_fd_set);
        FD_SET(tap.fd, &sock_fd_set);
        sock_fd = select(max_sock_fd, &sock_fd_set, 0, 0, &select_time);

        now = time(0);
        if (sock_fd > 0) {
            if (FD_ISSET(wan_sock, &sock_fd_set)) { //from wan
                recv_len = recvfrom(wan_sock,
                                    pkt_buf,
                                    3044,
                                    0,
                                    (struct sockaddr *)&recv_addr,
                                    (socklen_t *)&recv_addr_len);
                if (recv_len > 0) {
                    switch (pkt_buf[0]) {
                    //data
                    case DATA_TRANS: {
                        if (status > ETHNC_REG &&
                                recv_len > sizeof(struct ethn_data)) {
                            recv_len -= sizeof(struct ethn_data);
                            recv_len = TwoFishDecryptRaw(data_hdr->data, tf_buf, recv_len, tf_dec);
                            tap_write(tap.fd, tf_buf, recv_len);

                            if (recv_addr.sin_addr.s_addr == server_addr.sin_addr.s_addr &&
                                    recv_addr.sin_port == server_addr.sin_port) {
                                server_last_trans = now;
                            }

                            peer_upadte(tf_buf + 6, server_addr.sin_addr.s_addr, server_addr.sin_port);
                        }
                    }
                    break;
                    //reg
                    case REG_ACK: {
                        if (status != ETHNC_TRANS) {
                            if (recv_addr.sin_addr.s_addr == server_addr.sin_addr.s_addr &&
                                    recv_addr.sin_port == server_addr.sin_port) {
                                ethnc_reg_proc(reg_ack_hdr);
                            }
                        }
                    }
                    break;
                    //detect nat type
                    case NAT_DETECT: {
                        if (nat_type == NAT_TYPE_UNCHK) {
                            nat_type = natdtc_recv(recv_addr.sin_addr.s_addr,
                                                   recv_addr.sin_port,
                                                   pkt_buf, recv_len);
                            //try reg agin, update nat type
                            if (nat_type != NAT_TYPE_UNCHK) {
                                ethnc_reg_try(reg_hdr);
                                status = ETHNC_KEEPALIVE;
                            }
                        }
                    }
                    break;
                    //get clt info
                    case GET_CLT_ACK: {
                        get_wanaddr_proc(pkt_buf, recv_len);
                    }
                    break;
                    //punch
                    case WAN_PUNCH:
                    case WAN_PUNCH_ACK: {
                        wan_punch_proc(pkt_buf, recv_len, &recv_addr);
                    }
                    break;
                    //discv
                    case LAN_DISCV:
                    case LAN_DISCV_ACK: {
                        discv_proc(pkt_buf, recv_len, &recv_addr);
                    }
                    break;
                    //clt update: info / deled
                    case CLT_UPDATE: {
                        if (recv_len >= sizeof(struct ethn_clt_update)) {
                            clt_updated_proc((struct ethn_clt_update*)pkt_buf);
                        }
                    }
                    break;
                    }
                }
            } else if (FD_ISSET(tap.fd, &sock_fd_set)) { //from tap
                recv_len = tap_read(tap.fd, pkt_buf, 1500);
                if (recv_len > 0) {
                    if (recv_len > 14) {
                        data_hdr_tf->opt = DATA_TRANS;
                        memcpy(data_hdr_tf->dst_mac, pkt_buf, 6);
                        recv_len = TwoFishEncryptRaw(pkt_buf, data_hdr_tf->data, recv_len, tf_enc);
                        if (recv_len > 0) {
                            sendto(wan_sock,
                                   tf_buf,
                                   recv_len + sizeof(struct ethn_data),
                                   0,
                                   get_peer_addr(data_hdr_tf->dst_mac),
                                   sizeof(struct sockaddr_in));
                        }
                    }
                }
            }

            if (last_sec == now) {
                continue;
            }
        }

        last_sec = now;
        //peer's timer proc
        peer_timer();
        //detecting nat type, in trans or keepalive sate
        if (nat_type == NAT_TYPE_UNCHK &&
                status > ETHNC_REG) {
            nat_type = natdtc_timer();
            if (nat_type != NAT_TYPE_UNCHK) {
                ethnc_reg_try(reg_hdr);
                status = ETHNC_KEEPALIVE;
            }
        }
        //keepalive
        if (status == ETHNC_TRANS &&
                now - server_last_trans > UDP_TIMEOUT) {
            status = ETHNC_KEEPALIVE;
        }
        //try reging
        if (status != ETHNC_TRANS) {
            ethnc_reg_try(reg_hdr);
        }

        if (sleep_chk < now) {
            sleep_chk = now + 10;

            if (sleep_from_m != -1) {
                tm_p = gmtime(&now);
                now_m = ((tm_p->tm_hour + 8) % 24) * 60;
                now_m += tm_p->tm_min;
                if (now_m >= sleep_from_m && now_m <= sleep_to_m) {
                    sleep(sleep_to_m - sleep_from_m);
                }
            }
        }
    }
}

int main(int argc, char *const argv[])
{
    char server_port[8],
         ethn_key[32], ethn_mac[24], ethn_ip[16], ethn_mask[16], ethn_mtu[8],
         line_str[256], *p, *q,
         sleep_from[8], sleep_to[8], forward[2];
    unsigned char mac[6];
    unsigned int ethn_ip_ui, ethn_mask_ui;
    int i;
    FILE *fp;

    /*
    必须配置的参数：
    server_host     服务器名
    server_port     服务端口
    server_key      与服务器交互的key
    ethn_ip       ! tap口的ip
    ethn_mask       tap口的子网掩码
    ethn_mtu        tap口的mtu

    可选：
    ethn_mac        tap口的mac，*表示由系统分配
    sleep_from
    sleep_to        设置一天当中的某个时间段进行sleep状态，*表示不设置
    forward         wan环境下，是否启用转发模式
    */
    server_host[0] = '\0';
    strcpy(server_port, "35811");
    strcpy(server_key, "helloworld");
    strcpy(ethn_key, "helloworld35811");
    strcpy(ethn_mac, "*");
    strcpy(ethn_ip, "*");
    strcpy(ethn_mask, "255.255.255.0");
    strcpy(ethn_mtu, "1400");
    strcpy(sleep_from, "*");
    strcpy(sleep_to, "*");
    strcpy(forward, "0");

    if (argc > 1) {
        fp = fopen(argv[1], "r");
    }
    if (argc <= 1 || 0 == fp) {
        fp = fopen("ethnc.conf", "rw");
    }
    while (fgets(line_str, 255, fp)) {
        if (p = strchr(line_str, '\r')) {
            *p = '\0';
        }
        if (p = strchr(line_str, '\n')) {
            *p = '\0';
        }
        if (p = strchr(line_str, ':')) {
            q = p + 1;
            *p = '\0';
            printf("%-11s: %s\n", line_str, q);
            if (0 == strcmp(line_str, "server_host")) {
                strncpy(server_host, q, 63);
            } else if (0 == strcmp(line_str, "server_port")) {
                strncpy(server_port, q, 7);
            } else if (0 == strcmp(line_str, "server_key")) {
                strncpy(server_key, q, 31);
            } else if (0 == strcmp(line_str, "ethn_key")) {
                strncpy(ethn_key, q, 31);
            } else if (0 == strcmp(line_str, "ethn_mac")) {
                strncpy(ethn_mac, q, 23);
            } else if (0 == strcmp(line_str, "ethn_ip")) {
                strncpy(ethn_ip, q, 15);
            } else if (0 == strcmp(line_str, "ethn_mask")) {
                strncpy(ethn_mask, q, 15);
            } else if (0 == strcmp(line_str, "ethn_mtu")) {
                strncpy(ethn_mtu, q, 7);
            } else if (0 == strcmp(line_str, "sleep_from")) {
                strncpy(sleep_from, q, 7);
            } else if (0 == strcmp(line_str, "sleep_to")) {
                strncpy(sleep_to, q, 7);
            } else if (0 == strcmp(line_str, "forward")) {
                strncpy(forward, q, 2);
            }
        }
    }

    ethn_ip_ui = ntohl(inet_addr(ethn_ip));
    ethn_mask_ui = ntohl(inet_addr(ethn_mask));
    ethnc_ip_broadcast = htonl(ethn_ip_ui | ~ethn_mask_ui);

    //wan传输是否启动转发模式（不进行wan punch，但仍lan discv）
    mode_forward = (forward[0] == '0' ? 0 : 1);

    sleep_from_m = sleep_to_m = -1;
    if (strcmp(sleep_from, "*") && strcmp(sleep_to, "*")) {
        if (p = strchr(sleep_from, ':')) {
            *p = '\0';
            sleep_from_m = atoi(sleep_from) * 60;
            sleep_from_m += atoi(p + 1);
        }
        *p = ':';
        if (p = strchr(sleep_to, ':')) {
            *p = '\0';
            sleep_to_m = atoi(sleep_to) * 60;
            sleep_to_m += atoi(p + 1);
        }
        *p = ':';
    }

    tf_enc = TwoFishInit(ethn_key, strlen(ethn_key));
    tf_dec = TwoFishInit(ethn_key, strlen(ethn_key));

    memset(&server_addr, 0, sizeof(server_addr));
    i = atoi(server_port);
    server_addr.sin_port = htons(i);

    //打开、设置tap参数
    tap_open(&tap);
    if (strcmp(ethn_ip, "*")) {
        tap_set(&tap, 0, ethn_ip, ethn_mask, 0);
    }
    i = atoi(ethn_mtu);
    tap_set(&tap, 0, 0, 0, i);
    if (strcmp(ethn_mac, "*")) {
        tap_set(&tap, ethn_mac, 0, 0, 0);
    } else {
        tap_getmac(tap.fd, mac);
        sprintf(ethn_mac,
                "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    md5_key_mac_enc(server_key, tap.mac, md5_key);

    //保存配置
    if (fp) {
        fclose(fp);
        if (argc > 1) {
            fp = fopen(argv[1], "w");
        }
        if (argc <= 1 || 0 == fp) {
            fp = fopen("ethnc.conf", "w");
        }
        if (fp) {
            fprintf(fp, "server_host:%s\n", server_host);
            fprintf(fp, "server_port:%s\n", server_port);
            fprintf(fp, "server_key:%s\n", server_key);
            fprintf(fp, "ethn_key:%s\n", ethn_key);
            fprintf(fp, "ethn_mac:%s\n", ethn_mac);
            fprintf(fp, "ethn_ip:%s\n", ethn_ip);
            fprintf(fp, "ethn_mask:%s\n", ethn_mask);
            fprintf(fp, "ethn_mtu:%s\n", ethn_mtu);
            fprintf(fp, "sleep_from:%s\n", sleep_from);
            fprintf(fp, "sleep_to:%s\n", sleep_to);
            fprintf(fp, "forward:%s\n", forward);
            fflush(fp);
            fclose(fp);
        }
    }

    wan_reset();

    printf("ethnc running..\n");

    ethnc_loop();

    printf("ethnc stop.\n");
}