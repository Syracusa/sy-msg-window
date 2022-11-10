#ifndef MSG_WINDOW_H
#define MSG_WINDOW_H

#include <stdint.h>
#include <time.h>

typedef void (*msgwdw_sendpkt_t)(void *data, int len);
typedef void (*msgwdw_recvmsg_t)(void *data, int len);

typedef uint16_t msgwdw_idx_t;
typedef uint32_t msgwdw_bufidx_t;

#define MSGWINDOW_MSG               0
#define MSGWINDOW_RETRANSMIT        1
#define MSGWINDOW_NACK              2
#define MSGWINDOW_NOELEM            3
#define MSGWINDOW_HEARTBEAT         4
#define MSGWINDOW_FIRSTMSG          5
#define MSGWINDOW_RESOLVED          6

#pragma pack(push, 1)
typedef struct MsgCtrlHdr
{
    uint8_t ctrl;
    msgwdw_idx_t idx;
    uint16_t len;
    uint16_t checksum;
    uint8_t payload[];
}__attribute__((packed)) MsgCtrlHdr;
#pragma pack(pop)

typedef struct MsgElem
{
    unsigned char *buffer;
    uint64_t created;
    int len;
    msgwdw_idx_t msgidx;
} MsgElem;

typedef struct MsgListElem
{
    void* next; /* (MsgListElem*) */
    MsgElem* elem;
} MsgListElem;

typedef struct NackListElem
{
    void* next; /* (NackListElem*) */ 
    uint64_t created;
    uint64_t last_send;
    msgwdw_idx_t idx;
} NackListElem;

typedef struct MsgQueue
{
    MsgElem* elem;
    msgwdw_bufidx_t rear;
    msgwdw_bufidx_t front;
} MsgQueue;

typedef struct MsgWindow
{
    int max_msglen;

    msgwdw_sendpkt_t sendpkt;
    msgwdw_recvmsg_t recvmsg;

    msgwdw_idx_t sendidx;
    msgwdw_idx_t recvidx;
    msgwdw_idx_t frontidx;

    int valid_recvidx;
    unsigned int txbufnum;

    uint64_t last_timecheck;
    uint64_t nack_timeout_msec;
    uint64_t nack_interval_msec;

    uint64_t rxbuf_timeout_msec;

    MsgListElem *rxmsgbuf;

    MsgElem *txmsg_recordbuf; /* Circular buf that just rewrite old one */
    msgwdw_bufidx_t txelem_idx; /* Next write buf */

    NackListElem* nack_list;


    uint64_t last_10_msg_time;
    int txratelimit_10_msg_ms;
    uint64_t suppress_tx_until;
    int firstsend;

    uint64_t last_heartbeat_recv;
    uint64_t last_heartbeat_send;


    char *dbgname;
} MsgWindow;


MsgWindow *msgwdw_new(int msg_bufcnt,
                      int max_msglen,
                      msgwdw_sendpkt_t send,
                      msgwdw_recvmsg_t recv);

void msgwdw_finalize(MsgWindow *mw);

int msgwdw_txmsg(MsgWindow* mw,
                  void* msg,
                  int msglen);

void msgwdw_inject_rxpacket(MsgWindow *mw,
                 void *data,
                 int len);

void msgwdw_work(MsgWindow* mw);

static inline uint64_t time_ms()
{
    struct timespec ts;
    clock_gettime(0 /* CLOCK_REALTIME */, &ts);
    uint64_t res = 0;
    res += ts.tv_sec * 1000;
    res += ts.tv_nsec / 1000000;

    return res;
}

#endif