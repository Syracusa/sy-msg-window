#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "iface.h"
#include "msg_window.h"

int init_iface_server(int argv, char **argc)
{
    (void)argv;
    (void)argc;

    int server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(32100);

    int yes = 1;
    int ores = setsockopt(server_fd, SOL_SOCKET,
                          SO_REUSEADDR, &yes, sizeof(yes));

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));

    if (ores == -1)
    {
        printf("SO_REUSEADDR Fail!\n");
    }

    return server_fd;
}

int init_iface_client(int argv, char **argc)
{
    (void)argv;
    (void)argc;
    
    int client_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(32101);

    int yes = 1;
    int ores = setsockopt(client_fd, SOL_SOCKET,
                          SO_REUSEADDR, &yes, sizeof(yes));

    bind(client_fd, (struct sockaddr *)&addr, sizeof(addr));

    if (ores == -1)
    {
        printf("SO_REUSEADDR Fail!\n");
    }

    return client_fd;
}

void sendto_server(int fd, void *data, int len)
{
    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(32100);

    ssize_t slen = sendto(fd, data, len, 0,
                          (struct sockaddr *)&addr, 
                          sizeof(addr));
    if (slen <= 0)
    {
        printf("Send error %ld\n", sizeof(ssize_t));
    }
}

void sendto_client(int fd, void *data, int len)
{
    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_family = AF_INET;
    addr.sin_port = htons(32101);

    ssize_t slen = sendto(fd, data, len, 0,
                          (struct sockaddr *)&addr, 
                          sizeof(addr));
    if (slen <= 0)
    {
        printf("Send error %ld\n", sizeof(ssize_t));
    }
}

int recvfrom_server(int fd, void *buf)
{
    size_t buflen = MAX_MSG_SIZE + sizeof(MsgCtrlHdr);

    struct sockaddr_in rxaddr;
    socklen_t addrlen = sizeof(rxaddr);

    ssize_t rlen = recvfrom(fd, buf, buflen, 0,
                            (struct sockaddr *)&rxaddr, &addrlen);
    return rlen;
}

int recvfrom_client(int fd, void *buf)
{
    size_t buflen = MAX_MSG_SIZE + sizeof(MsgCtrlHdr);

    struct sockaddr_in rxaddr;
    socklen_t addrlen = sizeof(rxaddr);

    ssize_t rlen = recvfrom(fd, buf, buflen, 0,
                            (struct sockaddr *)&rxaddr, &addrlen);
    return rlen;
}