#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "msg_window.h"

static int valid_idx_diff;

#define PRT_DBGNAME()                             \
    do                                            \
    {                                             \
        if (mw && mw->dbgname)                    \
        {                                         \
            fprintf(stderr, " %s ", mw->dbgname); \
        }                                         \
    } while (0)

#define PRT_TIME()                                                                    \
    do                                                                                \
    {                                                                                 \
        struct timespec _curr;                                                        \
        clock_gettime(0, &_curr);                                                     \
        fprintf(stderr, "[%4lu:%4lu]", _curr.tv_sec % 1000, _curr.tv_nsec / 1000000); \
    } while (0)

#define MW_FREE(var) \
    do               \
    {                \
        free(var);   \
        var = NULL;  \
    } while (0);

/*======================= LOG =======================*/
#define __MW_DO_LOG 1

#if __MW_DO_LOG
#define MW_LOG(...)                                    \
    do                                                      \
    {                                                       \
        PRT_TIME();                                         \
        PRT_DBGNAME();                                      \
        fprintf(stderr, "[MsgWindow] " __VA_ARGS__); \
    } while (0)

#define MW_DEBUG(...)                                  \
    do                                                      \
    {                                                       \
        PRT_TIME();                                         \
        PRT_DBGNAME();                                      \
        fprintf(stderr, "[MsgWindow] " __VA_ARGS__); \
    } while (0)

#define MW_ERROR(...)                                        \
    do                                                            \
    {                                                             \
        PRT_TIME();                                               \
        PRT_DBGNAME();                                            \
        fprintf(stderr, "[MsgWindow ERROR] " __VA_ARGS__); \
    } while (0)

#define MW_VERBOSE(...) \
    do                       \
    {                        \
    } while (0)

#else /* mw_do_log*/

#define MW_LOG(...) \
    do                   \
    {                    \
    } while (0)
#define MW_DEBUG(...) \
    do                     \
    {                      \
    } while (0)

#if 0
#define MW_ERROR(...)                                        \
    do                                                            \
    {                                                             \
        PRT_TIME();                                               \
        PRT_DBGNAME();                                            \
        fprintf(stderr, "[MsgWindow ERROR] " __VA_ARGS__); \
    } while (0)
#else
#define MW_ERROR(...) \
    do                     \
    {                      \
    } while (0)
#endif

#define MW_VERBOSE(...) \
    do                       \
    {                        \
    } while (0)
#endif /* mw_do_log*/
/*===================================================*/

static void old_idx_recv(MsgWindow *mw,
                         MsgCtrlHdr *data,
                         int len);

static void check_nacklist_timeout(MsgWindow *mw);

static void check_nack_time(MsgWindow *mw);

static inline uint16_t calc_checksum(uint8_t *data,
                                     int len)
{
    uint16_t res = 0;

    int even_len = (len % 2 == 1) ? len - 1 : len;

    for (int i = 0; i < even_len; i += 2)
    {
        uint16_t *partial = (uint16_t *)(&data[i]);
        res += *partial;
    }

    if (even_len != len)
    {
        res += data[len - 1];
    }

    return res;
}

static inline int get_idx_diff(msgwdw_idx_t now,
                               msgwdw_idx_t old)
{
    if (now > old)
    {
        return now - old;
    }
    else
    {
        return old - now;
    }
}

static inline int is_old_idx(msgwdw_idx_t now,
                             msgwdw_idx_t last)
{
    int ret = 0;

    int diff = get_idx_diff(now, last);
    if (diff < valid_idx_diff)
    {
        if (now <= last)
            ret = 1;
    }
    else
    {
        if (last <= now)
        {
            ret = 1;
        }
    }

    return ret;
}

#if 0
static void log_nacklist(MsgWindow *mw)
{
    fprintf(stderr, "PRT NACKLIST\n");
    NackListElem *ne = mw->nack_list;
    while (ne)
    {
        fprintf(stderr, "%p:%u->", ne, ne->idx);
        ne = ne->next;
    }
    fprintf(stderr, "\n");
    fflush(stderr);
}
#endif

MsgWindow *msgwdw_new(int msg_bufcnt,
                      int max_msglen,
                      msgwdw_sendpkt_t send,
                      msgwdw_recvmsg_t recv)
{
    MsgWindow *mw = malloc(sizeof(MsgWindow));
    memset(mw, 0x00, sizeof(MsgWindow));
    mw->txbufnum = msg_bufcnt;
    mw->max_msglen = max_msglen;

    mw->recvmsg = recv;
    mw->sendpkt = send;

    mw->rxmsgbuf = NULL;
    mw->txratelimit_10_msg_ms = 20;

    /* Txbuffer init */
    mw->txmsg_recordbuf = malloc(sizeof(MsgElem) * msg_bufcnt);

    mw->txelem_idx = 0;
    for (int i = 0; i < msg_bufcnt; i++)
    {
        mw->txmsg_recordbuf[i].buffer = malloc(max_msglen);
        mw->txmsg_recordbuf[i].len = -1;
        mw->txmsg_recordbuf[i].msgidx = -1;
    }
    mw->sendidx = 0;
    mw->recvidx = 0;

    mw->valid_recvidx = 0;

    mw->nack_list = NULL;
    mw->nack_timeout_msec = 5000;
    mw->nack_interval_msec = 500;
    mw->rxbuf_timeout_msec = 5000;

    mw->last_heartbeat_recv = time_ms();
    mw->last_timecheck = time_ms();

    mw->dbgname = NULL;
    mw->firstsend = 1;

    valid_idx_diff = msg_bufcnt;

    MW_DEBUG("MsgWindow created\n");
    return mw;
}

void msgwdw_finalize(MsgWindow *mw)
{
    for (int i = 0; i < (int)(mw->txbufnum); i++)
    {
        MW_FREE(mw->txmsg_recordbuf[i].buffer);
    }
    MW_FREE(mw->txmsg_recordbuf);
    MW_FREE(mw);
    MW_DEBUG("MsgWindow finalized\n");
}

static MsgElem *new_msgelem(MsgWindow *mw,
                            MsgCtrlHdr *data,
                            int len)
{
    MsgElem *e;
    int msglen = len - sizeof(MsgCtrlHdr);
    e = malloc(sizeof(MsgElem));
    e->buffer = malloc(msglen);
    memcpy(e->buffer, data->payload, msglen);

    e->len = msglen;
    e->msgidx = data->idx;

    e->created = time_ms();
#if 0
    MW_DEBUG("New msgelem created. len : %d, seq : %u\n", e->len, e->msgidx);
#else 
    (void)mw;
#endif
    return e;
}

static void txmsg_record(MsgWindow *mw,
                         MsgCtrlHdr *data,
                         int len)
{
    MsgElem *e = &(mw->txmsg_recordbuf[mw->txelem_idx]);

    int msglen = len - sizeof(MsgCtrlHdr);
    memcpy(e->buffer, data->payload, msglen);
    e->len = msglen;
    e->msgidx = data->idx;
    e->created = time_ms();

#if 0
    if (data->idx % 100 == 0)
        MW_LOG("Txmsg idx %u buffered at %u\n",
            data->idx, mw->txelem_idx);
#else
    if (data->idx == 0)
        MW_LOG("Tx sequence reset to 0\n");
#endif
    mw->txelem_idx++;
    if (mw->txelem_idx >= mw->txbufnum)
    {
        mw->txelem_idx = 0;
    }
}
static void send_ctrl_pkt(MsgWindow *mw, MsgCtrlHdr *pkt, int len)
{
    pkt->len = len;
    pkt->checksum = 0;
    pkt->checksum = calc_checksum((uint8_t *)pkt, len);

    mw->sendpkt(pkt, len);
}

static void msgwdw_txmsg_internal(MsgWindow *mw,
                                  void *msg,
                                  int msglen,
                                  int retransmit_idx)
{
    MsgCtrlHdr *sendbuf =
        (MsgCtrlHdr *)malloc(mw->max_msglen + sizeof(MsgCtrlHdr));

    if (msglen > mw->max_msglen)
    {
        fprintf(stderr, "MsgWindow sendlen error(%d<%d)",
                mw->max_msglen, msglen);
    }
    else
    {
        /* Attach message ctrl header */
        if (mw->firstsend == 1)
        {
            sendbuf->ctrl = MSGWINDOW_FIRSTMSG;
            sendbuf->idx = mw->sendidx;
            mw->sendidx += 1;
            mw->firstsend = 0;
            MW_LOG("Tx first pkt idx %u\n", sendbuf->idx);
        }
        else if (retransmit_idx >= 0)
        {
            sendbuf->ctrl = MSGWINDOW_RETRANSMIT;
            sendbuf->idx = retransmit_idx;
            MW_VERBOSE("Tx retransmit idx %u\n", sendbuf->idx);
        }
        else
        {
            sendbuf->ctrl = MSGWINDOW_MSG;
            sendbuf->idx = mw->sendidx;
            mw->sendidx += 1;
        }

        int newlen = msglen + sizeof(MsgCtrlHdr);
        memcpy(sendbuf->payload, msg, msglen);

        if (retransmit_idx < 0) /* Buffer if no retransmit */
            txmsg_record(mw, sendbuf, newlen);

        send_ctrl_pkt(mw, sendbuf, newlen);
    }
    free(sendbuf);
}

static void do_ratelimit(MsgWindow* mw)
{
    uint64_t currtime_ms = time_ms();
    if (mw->sendidx % 10 == 0)
    {
        uint64_t interval = currtime_ms - mw->last_10_msg_time;
        if (interval < (uint64_t)mw->txratelimit_10_msg_ms)
        {
            mw->suppress_tx_until = currtime_ms;
            mw->suppress_tx_until += mw->txratelimit_10_msg_ms - interval;
        } 
    }
    mw->last_10_msg_time = currtime_ms;
}

int msgwdw_txmsg(MsgWindow* mw,
                  void* msg,
                  int msglen)
{
    msgwdw_work(mw);
    int res = 1;
    if (time_ms() < mw->suppress_tx_until) 
    {
        /* Suppress tx rate(IO fail detected) */
        res = -1;
    } 
    else 
    {
        do_ratelimit(mw);
        msgwdw_txmsg_internal(mw, msg, msglen, -1);
    }
    return res;
}


#define free_elembuf(_elem)  \
    do                       \
    {                        \
        free(_elem->buffer); \
        free(_elem);         \
        _elem = NULL;        \
    } while (0)

#if 0
static void free_elembuf(MsgElem *e)
{
    free(e->buffer);
    free(e);
    // MW_FREE(e->buffer);
    // MW_FREE(e);
}
#endif

static MsgElem *rxmsg_dequeue(MsgWindow *mw,
                              msgwdw_idx_t idx)
{
    MsgListElem *le = mw->rxmsgbuf;
    MsgListElem *priv = NULL;
    MsgElem *ret = NULL;

    while (le != NULL)
    {
        if (le->elem->msgidx == idx)
        {
            ret = le->elem;
            if (priv != NULL)
                priv->next = le->next;
            else
                mw->rxmsgbuf = le->next;
            MW_FREE(le);
            break;
        }
        priv = le;
        le = le->next;
    }

    return ret;
}

static void rxmsg_enqueue(MsgWindow *mw,
                          MsgCtrlHdr *data,
                          int len)
{
    MsgListElem *le = malloc(sizeof(MsgListElem));
    le->elem = new_msgelem(mw, data, len);
    le->next = mw->rxmsgbuf;
    mw->rxmsgbuf = le;
}

static int remove_nack_elem(MsgWindow *mw,
                            msgwdw_idx_t idx)
{
    NackListElem *ne = mw->nack_list;
    NackListElem *priv = NULL;
    int ret = 0;

    while (ne)
    {
        if (ne->idx == idx)
        {
            if (priv == NULL)
            {
                mw->nack_list = ne->next;
            }
            else
            {
                priv->next = ne->next;
            }
            MW_FREE(ne);
            ret = 1;
            break;
        }

        priv = ne;
        ne = ne->next;
    }

    if (ret == 1)
    {
        MW_VERBOSE("Nacklist %u removed\n", idx);
    }
    else
    {
        MW_VERBOSE("Can't remove nacklist %u\n", idx);
    }

    return ret;
}

static void send_buffered(MsgWindow *mw)
{
    /* Check if buffered msg exist */
    MsgElem *e = rxmsg_dequeue(mw, mw->recvidx + 1);
    while (e)
    {
        mw->recvidx = e->msgidx;
        mw->recvmsg(e->buffer, e->len);
        free_elembuf(e);
        e = rxmsg_dequeue(mw, mw->recvidx + 1);
    }
}

static void recv_msg_now(MsgWindow *mw,
                         MsgCtrlHdr *data,
                         int len)
{
    mw->recvmsg(data->payload, len - sizeof(MsgCtrlHdr));
    send_buffered(mw);
}

static void retransmit_nack(MsgWindow *mw)
{
    MsgCtrlHdr sendbuf;
    sendbuf.ctrl = MSGWINDOW_NACK;
    uint64_t currtime = time_ms();
    NackListElem *ne = mw->nack_list;

    while (ne)
    {
        if (currtime - ne->last_send > mw->nack_interval_msec)
        {
            sendbuf.idx = ne->idx;
            MW_LOG("Retransmit NACK idx %u\n", ne->idx);
            ne->last_send = currtime;
            send_ctrl_pkt(mw, &sendbuf, sizeof(sendbuf));
        }
        ne = ne->next;
    }
}

static void check_rxbuf_timeout(MsgWindow *mw)
{
    MsgListElem *le = mw->rxmsgbuf;
    MsgListElem *priv = NULL;
    while (le)
    {
        if (mw->rxbuf_timeout_msec <= time_ms() - le->elem->created)
        {
            MW_LOG("Rxbuf entry idx %u timeouted\n", le->elem->msgidx);
            if (priv)
            {
                priv->next = le->next;
            }
            else
            {
                mw->rxmsgbuf = le->next;
            }
            MsgListElem *tmp = le->next;
            free_elembuf(le->elem);
            MW_FREE(le);
            le = tmp;
        }
        else
        {
            le = le->next;
        }
    }
}

static void check_nack_time(MsgWindow *mw)
{
    /* Suppress check interval to 10ms */
    if (time_ms() - mw->last_timecheck > 10)
    {
        check_rxbuf_timeout(mw);
        /* Remove timeouted nack */
        check_nacklist_timeout(mw);
        /* Retrasmit nack */
        retransmit_nack(mw);
    }
}

static int nack_elem_exist(MsgWindow *mw,
                           msgwdw_idx_t idx)
{
    int res = 0;
    NackListElem *ne = mw->nack_list;

    while (ne)
    {
        if (ne->idx == idx)
        {
            res = 1;
            break;
        }
        ne = ne->next;
    }
    return res;
}

static int check_rxidx_buffed(MsgWindow *mw,
                              msgwdw_bufidx_t idx)
{
    MsgListElem *e = mw->rxmsgbuf;
    int res = 0;

    while (e)
    {
        if (e->elem->msgidx == idx)
        {
            res = 1;
            break;
        }
        e = e->next;
    }
    return res;
}

static void send_nack(MsgWindow *mw, msgwdw_idx_t idx)
{
    MsgCtrlHdr msg;
    msg.ctrl = MSGWINDOW_NACK;
    msg.idx = idx;

    send_ctrl_pkt(mw, &msg, sizeof(msg));
}

static void handle_lost_idx(MsgWindow* mw, 
                            msgwdw_idx_t start, 
                            msgwdw_idx_t end)
{
    for (int lostidx = start; lostidx < end; lostidx++){
        /* Check if elem already exist */
        if (!nack_elem_exist(mw, lostidx) &&
            !check_rxidx_buffed(mw, lostidx)) {
            NackListElem *nle = malloc(sizeof(NackListElem));
            nle->created = time_ms();
            nle->last_send = time_ms();
            nle->idx = lostidx;

            nle->next = mw->nack_list;
            mw->nack_list = nle;

            send_nack(mw, lostidx);
            MW_LOG("Add nacklist idx %u\n", lostidx);
        }
        lostidx += 1;
    }
}

static void jumped_idx_recv(MsgWindow *mw,
                            MsgCtrlHdr *data,
                            int len)
{
    handle_lost_idx(mw, mw->recvidx + 1, data->idx);

    if (!check_rxidx_buffed(mw, data->idx)) {
        rxmsg_enqueue(mw, data, len);

        MW_VERBOSE("Msgidx %u buffered\n", data->idx);
    } else {
        MW_LOG("Already buffered idx %u\n", data->idx);
    }
}

static void clean_rxbuf(MsgWindow *mw)
{
    MsgListElem *le = mw->rxmsgbuf;
    MsgListElem *priv = NULL;

    while (le != NULL)
    {
        priv = le;
        le = le->next;

        free_elembuf(priv->elem);
        MW_FREE(priv);
    }

    mw->rxmsgbuf = NULL;
}

static void reset_nack_list(MsgWindow *mw)
{
    NackListElem *ne = mw->nack_list;
    while (ne)
    {
        NackListElem *priv = ne;
        ne = ne->next;
        MW_FREE(priv);
    }
    mw->nack_list = NULL;
}

static void invalid_idx_recv(MsgWindow *mw,
                             MsgCtrlHdr *data,
                             int len)
{
    int diff = get_idx_diff(data->idx, mw->recvidx);
    if (diff > valid_idx_diff)
    {
        MW_ERROR("Recv insane idx... reset recvidx to %u\n",
                 data->idx);

        reset_nack_list(mw);
        clean_rxbuf(mw);

        mw->recvidx = data->idx;
        mw->valid_recvidx = 1;
        recv_msg_now(mw, data, len);
    }
    else if (is_old_idx(data->idx, mw->recvidx))
    {
        MW_ERROR("Recv old idx(expected %u recv %u)\n",
                 mw->recvidx + 1, data->idx);
        old_idx_recv(mw, data, len);
    }
    else
    {
        MW_VERBOSE("Recv jumped idx(expected %u recv %u)\n",
                 mw->recvidx + 1, data->idx);
        jumped_idx_recv(mw, data, len);
    }
}

static void recv_msg(MsgWindow *mw,
                     MsgCtrlHdr *data,
                     int len)
{
    msgwdw_idx_t expected = mw->recvidx + 1;
    if (mw->valid_recvidx == 1 &&
        data->idx != expected)
    {
        invalid_idx_recv(mw, data, len);
    }
    else
    {
        mw->recvidx = data->idx;
        mw->valid_recvidx = 1;
        recv_msg_now(mw, data, len);
    }
}

static void old_idx_recv(MsgWindow *mw,
                         MsgCtrlHdr *data,
                         int len)
{
    /* Check nack list */
    NackListElem *nle = mw->nack_list;
    int dup = 1;
    while (nle)
    {
        if (nle->idx == data->idx)
        {
            /* Assume as retrasmit */
            MW_ERROR("Expected retransmit but no flag(idx : %u)\n",
                     data->idx);
            data->ctrl = MSGWINDOW_RETRANSMIT;
            remove_nack_elem(mw, data->idx);

            recv_msg(mw, data, len);
            dup = 0;
            break;
        }
        nle = nle->next;
    }

    if (dup)
        MW_LOG("Duplicated message expected, Drop. idx %u\n",
               data->idx);
}

static void check_nacklist_timeout(MsgWindow *mw)
{
    NackListElem *ne = mw->nack_list;
    NackListElem *priv = NULL;
    while (ne)
    {
        if (mw->nack_timeout_msec <= time_ms() - ne->created)
        {
            MW_LOG("NACK entry idx %u timeouted\n", ne->idx);
            if (ne->idx > mw->recvidx){
                mw->recvidx = ne->idx; /* Assume recved */
            }

            if (priv)
            {
                priv->next = ne->next;
            }
            else
            {
                mw->nack_list = ne->next;
            }
            NackListElem *tmp = ne->next;
            MW_FREE(ne);
            ne = tmp;
        }
        else
        {
            ne = ne->next;
        }
    }
}

static void retransmit_msg(MsgWindow *mw,
                           msgwdw_idx_t idx)
{
    int found = 0;
    for (int i = 0; i < (int)(mw->txbufnum); i++)
    {
        MsgElem *buf = &(mw->txmsg_recordbuf[i]);
        if (buf->len > 0 && buf->msgidx == idx)
        {
            MW_ERROR("Msgidx %u retransmit\n", idx);
            found = 1;
            msgwdw_txmsg_internal(mw, buf->buffer, buf->len, idx);
            break;
        }
    }

    if (found == 0)
    {
        MW_ERROR("Msgidx %u retransmit fail (no such entry)\n", idx);
        MsgCtrlHdr msg;
        msg.ctrl = MSGWINDOW_NOELEM;
        msg.idx = idx;
        send_ctrl_pkt(mw, &msg, sizeof(msg));
    }
}

static int is_pkt_ok(MsgWindow *mw, void *data, int len)
{
    int res = 1;

    MsgCtrlHdr *hdr = data;
    if (len != hdr->len)
    {
        MW_ERROR("MALFORMED PACKET(Length unmatch %u != %d)\n",
                 hdr->len, len);
        res = 0;
    }

    uint16_t checksum = hdr->checksum;
    hdr->checksum = 0;
    uint16_t calcd = calc_checksum((uint8_t *)data, len);

    if (checksum != calcd)
    {
        MW_ERROR("MALFORMED PACKET(Checksum %u != %u)\n",
                 checksum, calcd);
        res = 0;
    }

    return res;
}

#define SUPPRESS_TX_TIME 5000
static void suppress_tx(MsgWindow* mw)
{
    MW_LOG("IO fail detected... Suppress tx\n");
    mw->suppress_tx_until = time_ms() + SUPPRESS_TX_TIME;
}


#define HEARTBEAT_SEND_INTERVAL_MS 1000
#define HEARTBEAT_DROP_ASSUME_TIME 1500
static void check_heartbeat(MsgWindow* mw)
{
    uint64_t currtime_ms = time_ms();

    /* Send heartbeat */
    if (mw->last_heartbeat_send + HEARTBEAT_SEND_INTERVAL_MS < currtime_ms)
    {
#if 1
        MW_LOG("Send heartbeat\n");
#endif
        MsgCtrlHdr msg;
        msg.ctrl = MSGWINDOW_HEARTBEAT;
        msg.idx = mw->sendidx;
        send_ctrl_pkt(mw, &msg, sizeof(msg));
        mw->last_heartbeat_send = currtime_ms;
    }

    /* Check peer heartbeat time */
    if (mw->last_heartbeat_recv + HEARTBEAT_DROP_ASSUME_TIME < currtime_ms)
    {
        /* Peer heartbeat dropped */
        // MW_LOG("Can't hear peer heartbeat. Suppress tx\n");   
        mw->last_heartbeat_recv = currtime_ms;
        mw->suppress_tx_until = time_ms() + HEARTBEAT_DROP_ASSUME_TIME;
    }
}

void msgwdw_work(MsgWindow* mw)
{
    check_nack_time(mw);
    check_heartbeat(mw);
}

static void check_resolve(MsgWindow* mw)
{
    if (mw->nack_list == NULL && mw->rxmsgbuf == NULL)
    {
        MsgCtrlHdr msg;
        msg.ctrl = MSGWINDOW_RESOLVED;
        send_ctrl_pkt(mw, &msg, sizeof(msg));
        MW_LOG("Congestion resolved\n");
    }
}

void msgwdw_inject_rxpacket(MsgWindow *mw,
                            void *data,
                            int len)
{
    if (is_pkt_ok(mw, data, len))
    {
        MsgCtrlHdr *hdr = data;

        switch (hdr->ctrl)
        {
        case MSGWINDOW_FIRSTMSG:
            MW_LOG("Firstmsg recved.. reset nacklist\n");
            mw->recvidx = hdr->idx - 1;
            mw->lastrecv = hdr->idx;
            reset_nack_list(mw);
            recv_msg(mw, data, len);
            break;
        case MSGWINDOW_MSG:
            mw->lastrecv = hdr->idx;
            remove_nack_elem(mw, hdr->idx);
            recv_msg(mw, data, len);
            break;
        case MSGWINDOW_RETRANSMIT:
            MW_LOG("Retransmitted message idx %u recvd\n", hdr->idx);
            remove_nack_elem(mw, hdr->idx);
            recv_msg(mw, data, len);
            check_resolve(mw);
            break;
        case MSGWINDOW_NACK:
            suppress_tx(mw);
            retransmit_msg(mw, hdr->idx);
            break;
        case MSGWINDOW_NOELEM:
            MW_LOG("Sender responsed no element idx %u\n", hdr->idx);
            if (mw->recvidx < mw->lastrecv){
                mw->recvidx = mw->lastrecv;
                reset_nack_list(mw);
                clean_rxbuf(mw);
            }
            send_buffered(mw);
            break;
        case MSGWINDOW_HEARTBEAT:
            if (mw->valid_recvidx == 1 && hdr->idx - 1 != mw->recvidx) {
                MW_LOG("Peer sendidx != recvidx (%u != %u)\n",
                       hdr->idx - 1, mw->recvidx);
                handle_lost_idx(mw, mw->recvidx + 1, hdr->idx);
            }
            mw->last_heartbeat_recv = time_ms();
            break;
        case MSGWINDOW_RESOLVED:
            MW_LOG("Receiver response congestion resolved\n");
            mw->suppress_tx_until = time_ms();
            break;
        default:
            MW_LOG("Unavailable ctrl code %u\n", hdr->idx);
            break;
        }
    }
    msgwdw_work(mw);
}
