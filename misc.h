#ifndef __MISC_H
#define __MISC_H

int log_init(char *file_name);
int log_line(char *str);
void log_clear();

void md5_key_mac_enc(char key[33],
                     unsigned char mac[6],
                     unsigned char out[16]);

int sock_open(char *ip, unsigned short port);

#endif