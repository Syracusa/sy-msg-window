#ifndef IFACE_H
#define IFACE_H

#define MAX_MSG_SIZE 4000

int init_iface_server(int argv, char **argc);
int init_iface_client(int argv, char **argc);

void sendto_server(int fd, void *data, int len);
void sendto_client(int fd, void *data, int len);

int recvfrom_server(int fd, void *buf);
int recvfrom_client(int fd, void *buf);

#endif