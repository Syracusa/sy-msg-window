#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <signal.h>

#include "msg_window.h"
#include "test.h"

int fd;
MsgWindow *clientwd;

/* Call by lib */
void client_send_sim_pkt(void *data, int len)
{
    // printf("Client wanna send pkt(len : %d)\n", len);

#if 0
    /* Make ERROR */
    static char *reorderbuf = NULL;
    static int reorderbuflen = 0;

    if (rand() % 100 == 1)
    {
        printf("length error occured\n");
        len -= 1;
    }

    if (rand() % 100 == 0)
    {
        printf("Bit error occured\n");

        uint8_t *bb = data;
        bb[rand() % len] -= 1;
    }

    if (rand() % 10 == 0)
    {
        printf("Packet dropped\n");
        return; /* Drop */
    }

    if (rand() % 100 == 0 && reorderbuf == NULL)
    {
        reorderbuf = malloc(len);
        reorderbuflen = len;
        memcpy(reorderbuf, data, len);

        printf("Packet reorder buffered\n");
    }
    else
    {
        unsigned char peerbuf[MAX_MSG_SIZE + sizeof(MsgCtrlHdr)];
        memcpy(peerbuf, data, len);

        sendto_server(fd, peerbuf, len);

        if (reorderbuf)
        {
            printf("Send buffered(reordered)\n");
            sendto_server(fd, reorderbuf, reorderbuflen);

            free(reorderbuf);
            reorderbuf = NULL;
            reorderbuflen = 1;
        }
    }
#else
    unsigned char peerbuf[MAX_MSG_SIZE + sizeof(MsgCtrlHdr)];
    memcpy(peerbuf, data, len);

    sendto_server(fd, peerbuf, len);
#endif
}

void client_recv_sim_msg(void *data, int len)
{
    (void)data;
    (void)len;
#if 0
    SimMsg *msg = data;

    printf("Client recved message(seq : %u, len : %d)\n",
           msg->seq, len);
#endif
}

static void tryread(MsgWindow *mw)
{
    static unsigned char recvbuf[MAX_MSG_SIZE + sizeof(MsgCtrlHdr)];

    fd_set read_fs;
    FD_ZERO(&read_fs);
    FD_SET(fd, &read_fs);

    struct timeval tv = {0, 10};
    int ready = select(fd + 1, &read_fs, NULL, NULL, &tv);
    if (ready)
    {
        if (FD_ISSET(fd, &read_fs))
        {
            int rlen = recvfrom_server(fd, recvbuf);

            if (rlen > 0)
                msgwdw_inject_rxpacket(mw, recvbuf, rlen);
            // else
            //     printf("Recv fail %d\n", rlen);
        }
    }
}

void send_sim_msg(int idx, MsgWindow *mw)
{
    static unsigned char txmsgbuf[MAX_MSG_SIZE];
    SimMsg *msg = (SimMsg *)txmsgbuf;

    int msglen = rand() % MAX_MSG_SIZE;
    if (msglen < (int)(sizeof(SimMsg) + 1))
    {
        msglen = (int)(sizeof(SimMsg) + 1);
    }
    unsigned char cmd = rand() % 256;
    memset(msg->payload, cmd, msglen - sizeof(SimMsg));

    msg->len = msglen;
    msg->seq = idx;

    int txres = msgwdw_txmsg(mw, msg, msglen);
    while (txres == -1){
        usleep(10000);
        tryread(mw);
        msgwdw_work(mw);
        txres = msgwdw_txmsg(mw, msg, msglen);
    }
}


static void gen_simtraffic_loop(MsgWindow *mw, int interval_ms)
{
    int cli_sendidx = 0;
    uint64_t last_send = time_ms();



    while (1)
    {
        msgwdw_work(mw);
        tryread(mw);
#if 1
        if ((int)(time_ms() - last_send) > interval_ms)
        {
            send_sim_msg(cli_sendidx++, mw);
            last_send += interval_ms;
        }
#else
    send_sim_msg(cli_sendidx++, mw);
#endif
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

    if (argv > 1)
    {
        fd = init_iface_client(argv, argc);
        printf("Sockfd : %d\n", fd);

        clientwd = msgwdw_new(1000, MAX_MSG_SIZE,
                            client_send_sim_pkt,
                            client_recv_sim_msg);

        clientwd->dbgname = "Client";

        signal(SIGINT, io_finalize);
        gen_simtraffic_loop(clientwd, atoi(argc[1]));

    }
    else 
    {
        fprintf(stderr, " Usage : ./%s {Interval}\n", argc[0]);
    }
    return 0;
}