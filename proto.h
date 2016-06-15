#ifndef __PROTO_H
#define __PROTO_H

enum ETHN_OPT {
	REG_REQ = 1,
	REG_ACK,
	DATA_TRANS,
	DATA_NAK,
	GET_CLTS,
	NAT_DETECT,
	GET_CLT,
	GET_CLT_ACK,
	WAN_PUNCH,
	WAN_PUNCH_ACK,
	LAN_DISCV,
	LAN_DISCV_ACK,
	CLT_UPDATE
};

enum NATDT_STEP {
	CHK_SYMMETRIC_REQ_1 = 1,
	CHK_SYMMETRIC_ACK_1,
	CHK_SYMMETRIC_REQ_2,
	CHK_SYMMETRIC_ACK_2,
	CHK_FULLCONE_CLTREQ,
	CHK_FULLCONE_SRVACK
};

enum NAT_TYPE {
	NAT_TYPE_SYMMETRIC = 0,
	NAT_TYPE_FULLCONE,
	NAT_TYPE_RESTRIC,
	NAT_TYPE_UNCHK,
	NAT_TYPE_FORWARD
};

enum CLT_UPD_CODE {
	CLT_UPD_INFO,
	CLT_UPD_DELED
};

struct ethn_reg_req {
	unsigned char opt;
	unsigned char nat_type;
	unsigned char ethn_mac[6];
	unsigned char lan_port[2];
	unsigned char md5_key[16];
};

struct ethn_reg_ack {
	unsigned char opt;
	unsigned char md5_key[16];
	unsigned char wan_ip[4];
	unsigned char wan_port[2];
};

struct ethn_data {
	unsigned char opt;
	unsigned char dst_mac[6];
	unsigned char data[0];
};

struct ethn_cltinfo {
	unsigned char opt;
	unsigned char code;
	unsigned char nat_type;
	unsigned char ethn_mac[6];
	unsigned char wan_ip[4];
	unsigned char wan_port[2];
	unsigned char lan_port[2];
};

struct nat_detect {
	unsigned char opt;
	unsigned char step;
	unsigned char wan_ip[4];
	unsigned char wan_port[2];
};

struct ethn_clt_update {
	unsigned char opt;
	unsigned char code;
	unsigned char ethn_mac[6];
};

#endif