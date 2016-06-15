#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "proto.h"
#include "md5.h"

/*
写日志
*/
static FILE *log_fd = 0;

//打开日志文件
int log_init(char *file_name)
{
	log_fd = fopen(file_name, "a");

	return 0 == log_fd ? -1 : 0;
}

//写一行日志，日志前自动添加写的日期
int log_line(char *str)
{
	time_t now;
	struct tm *p;

	if (log_fd && str) {
		time(&now);
		p = gmtime(&now);
		fprintf(log_fd,
		        "%04d-%02d-%02d %02d:%02d:%02d %s\n",
		        1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday,
		        (8 + p->tm_hour) % 24, p->tm_min, p->tm_sec,
		        str);
		fflush(log_fd);
	}

	return -1;
}

void log_clear()
{
	if (log_fd) {
		fclose(log_fd);
		log_fd = 0;
	}
}

/*
计算key与mac的md5值
key[0],key[1]..key[31],mac[0],mac[1]..mac[7] > md5() > out
*/
void md5_key_mac_enc(char key[33],
                     unsigned char mac[6],
                     unsigned char out[16])
{
	int len;
	MD5_CTX md5;
	unsigned char buf[38];

	len = strlen(key);
	if (len > 32) {
		len = 32;
	}

	strncpy(buf, key, len);
	memcpy(&buf[len], mac, 6);
	len += 6;

	MD5Init(&md5);
	MD5Update(&md5, buf, len);
	MD5Final(&md5, out);
}

/*
创建一个可以收发广播包的udp sock

ip		sock所绑定的ip，"0.0.0.0"表示所有接口上的ip
port 	sock所绑定的udp端口，0表示由系统自动分配一个未使用的端口

返值：-1 创建sock失败，其它，sock创建成功
*/
int sock_open(char *ip, unsigned short port)
{
	struct sockaddr_in addr;
	int sock_opt;
	int sock;

	//create
	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		return -1;
	}

	//enable broadcast & reuseaddr
	sock_opt = 1;
	setsockopt(sock,
	           SOL_SOCKET,
	           SO_BROADCAST | SO_REUSEADDR,
	           (char *)&sock_opt,
	           sizeof(sock_opt));

	//bind
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		return -1;
	}

	return sock;
}