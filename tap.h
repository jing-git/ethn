#ifndef __TAP_LINUX_H
#define __TAP_LINUX_H

struct ethn_tap {
    int fd;
    char name[32];
    unsigned char mac[6];
    unsigned int ip;
    unsigned int mask;
    unsigned short mtu;
};

int tap_open(struct ethn_tap *tap);
void tap_close(int fd);

int tap_read(int fd, unsigned char *buf, int len);
int tap_write(int fd, unsigned char *buf, int len);

int tap_getname(int fd, char *tap_name);
int tap_getmac(int fd, unsigned char *mac_addr);

int tap_set_name(struct ethn_tap *tap, char *name);
int tap_set(struct ethn_tap *tap,
            char *mac,
            char *ip,
            char *mask,
            unsigned short mtu);

#endif
