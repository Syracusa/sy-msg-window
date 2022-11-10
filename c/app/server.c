#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include "msg_window.h"
#include "test.h"

#define MAX_MSG_SIZE 4000

int fd;
MsgWindow *serverwd;

/* Call by lib */
void server_send_sim_pkt(void *data, int len)
{
    unsigned char peerbuf[MAX_MSG_SIZE + 96];
    memcpy(peerbuf, data, len);

    sendto_client(fd, data, len);
}

void server_recv_sim_msg(void *data, int len)
{
    SimMsg *msg = data;
    static uint16_t expected_seq = 0;

    if (expected_seq != msg->seq)
    {
        printf("Sequence unmatch! %u <-> %u\n",
               expected_seq, msg->seq);
        expected_seq = msg->seq + 1;
    }
    else
    {
        expected_seq++;
    }

#if 1
    if ( msg->seq  == 0)
    {
        printf("Server recvseq reset to 0(len : %d)\n", len);
    }
#else 
    printf("Server recved message(seq : %u, len : %d)\n",
            msg->seq, len);
#endif
}

static void tryread(MsgWindow *mw)
{
    static unsigned char recvbuf[MAX_MSG_SIZE + 96];

    fd_set read_fs;
    FD_ZERO(&read_fs);
    FD_SET(fd, &read_fs);

    struct timeval tv = {1, 0};
    int ready = select(fd + 1, &read_fs, NULL, NULL, &tv);
    if (ready)
    {
        if (FD_ISSET(fd, &read_fs))
        {
            int rlen = recvfrom_client(fd, recvbuf);

            if (rlen > 0)
                msgwdw_inject_rxpacket(mw, recvbuf, rlen);
            // else
            //     printf("Recv fail %d\n", rlen);
        }
    }
}

static void recv_loop(MsgWindow *mw)
{
    // static unsigned char recvbuf[MAX_MSG_SIZE + sizeof(MsgCtrlHdr)];

    while (1)
    {
        msgwdw_work(mw);
        tryread(mw);

        // ssize_t rlen = recvfrom_client(fd, recvbuf);
        // if (rlen > 0)
        //     msgwdw_inject_rxpacket(mw, recvbuf, rlen);
        // else
        //     printf("Recv fail %ld\n", rlen);
    }
}

static void io_finalize()
{
    close(fd);
    printf("FD closed\n");
    exit(2);
}

int main(int argv, char **argc)
{
    srand(time(NULL));
    fd = init_iface_server(argv, argc);

    printf("Sockfd : %d\n", fd);

    serverwd = msgwdw_new(1000, MAX_MSG_SIZE,
                          server_send_sim_pkt,
                          server_recv_sim_msg);
    serverwd->dbgname = "Server";
    signal(SIGINT, io_finalize);
    recv_loop(serverwd);
    return 0;
}