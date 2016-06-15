#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>

#include "tap.h"

int tap_open(struct ethn_tap *tap)
{
	int fd;
	struct ifreq ifr;
	char buf[128];

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		close(fd);
		return -1;
	}

	if (tap) {
		tap->fd = fd;
		if (0 == tap_getname(fd, buf)) {
			strncpy(tap->name, buf, 31);
		} else {
			tap->name[0] = '\0';
		}
		tap_getmac(fd, tap->mac);
	}

	return fd;
}

void tap_close(int fd)
{
	if (-1 != fd) {
		close(fd);
	}
}

int tap_read(int fd, unsigned char *buf, int len)
{
	return (read(fd, buf, len));
}

int tap_write(int fd, unsigned char *buf, int len)
{
	return (write(fd, buf, len));
}

int tap_getname(int fd, char *tap_name)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	if (ioctl(fd, TUNGETIFF, (void *)&ifr) < 0) {
		return -1;
	}

	strcpy(tap_name, ifr.ifr_name);

	return 0;
}

int tap_getmac(int fd, unsigned char *mac_addr)
{
	int sock;
	struct ifreq ifr;
	char tap_name[256];

	if (tap_getname(fd, tap_name)) {
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	sock = socket(PF_INET, SOCK_DGRAM, 0);
	strcpy(ifr.ifr_name, tap_name);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		return -1;
	} else {
		memcpy(mac_addr, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);
	}
	close(sock);

	return 0;
}

int tap_set_name(struct ethn_tap *tap, char *name)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	if (ioctl(tap->fd, TUNSETIFF, (void *)&ifr) < 0) {
		close(tap->fd);
		return -1;
	}

	strncpy(tap->name, name, 31);

	return 0;
}

int tap_set(struct ethn_tap *tap,
            char *mac,
            char *ip,
            char *mask,
            unsigned short mtu)
{
	unsigned char MAC_0[6] = {0};
	char buf[128];

	if (mac) {
		sprintf(buf,
		        "/sbin/ifconfig %s down",
		        tap->name);
		system(buf);

		sprintf(buf,
		        "/sbin/ifconfig %s hw ether %s up",
		        tap->name, mac);
		system(buf);

		tap_getmac(tap->fd, tap->mac);
	}

	if (ip && mask) {
		sprintf(buf,
		        "/sbin/ifconfig %s %s netmask %s up",
		        tap->name, ip, mask);
		system(buf);

		tap->ip = inet_addr(ip);
		tap->mask = inet_addr(mask);
	}

	if (mtu) {
		sprintf(buf,
		        "/sbin/ifconfig %s mtu %d up",
		        tap->name, mtu);
		system(buf);

		tap->mtu = mtu;
	}

	return 0;
}
