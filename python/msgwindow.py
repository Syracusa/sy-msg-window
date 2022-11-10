from collections import deque
import time
import struct

def time_ms():
    return time.time_ns() / 1000000

class MsgWindowPkt:
    hdrsz = 7

    def __init__(self):
        self.ctrl = 0
        self.idx = 0
        self.len = 0
        self.checksum = 0
        self.msg = None

    def unpack(self, bin):
        self.ctrl, self.idx,
        self.msglen, self.checksum,
        self.msg = struct.unpack(f'=BHHH{len(bin) - 7}s', bin)

    def pack(self):
        bin = struct.pack(f'=BHHH{len(self.msg)}s',
                          self.ctrl, self.idx, self.msglen,
                          self.checksum, self.msg)
        return bin

class NackElem:
    def __init__(self, idx):
        self.idx = idx
        self.created = time_ms()
        self.last_send = time_ms()

class MsgElem:
    def __init__(self, data: MsgWindowPkt):
        self.pkt = data
        self.created = time_ms()

class MsgWindow:
    MSGWINDOW_MSG = 0
    MSGWINDOW_RETRANSMIT = 1
    MSGWINDOW_NACK = 2
    MSGWINDOW_NOELEM = 3
    MSGWINDOW_HEARTBEAT = 4
    MSGWINDOW_FIRSTMSG = 5
    MSGWINDOW_RESOLVED = 6

    def calc_checksum(data, len):
        res = 0

        if len % 2 == 1:
            even_len = len - 1
        else:
            even_len = len

        checksum = 0
        i = 0
        while i < even_len:
            partial = struct.unpack('<H', data[i:i+2])
            checksum += partial
            i += 2

        if even_len != len:
            partial = struct.unpack('<B', data[len - 1])

        return checksum

    def get_idx_diff(now, old):
        if now > old:
            return now - old
        else:
            return old - now

    def parse_hdr(data, len):
        ctrl, idx, msglen, checksum, msg = struct.unpack(
            f'<BHHH{len - 7}s', data)
        return (ctrl, idx, msglen, checksum, msg)

    def get_next_idx(idx) -> int:
        next = idx + 1
        if next > 65535:
            next = 0
        return next

# =======================================================================
    def mw_debug(self, level, text):
        if self.loglevel >= level:
            print(text)

    def __init__(self, msg_bufcnt, max_msglen, send_f, recv_f, dbgname):
        self.valid_idx_diff = msg_bufcnt
        self.txbufnum = msg_bufcnt
        self.max_msglen = max_msglen

        self.recvmsg = recv_f
        self.sendpkt = send_f

        self.txratelimit_10_msg_ms = 0

        self.rxmsgbuf = {}
        self.txmsg_recordbuf = {}

        self.sendidx = 0
        self.recvidx = 0

        self.valid_recvidx = 0

        self.nack_list = {}
        self.nack_timeout_msec = 5000
        self.nack_interval_msec = 500
        self.rxbuf_timeout_msec = 5000
        self.txbuf_timeout_msec = 5000

        self.last_heartbeat_send = 0
        self.last_heartbeat_recv = time_ms()
        self.last_timecheck = time_ms()

        self.dbgname = dbgname
        self.loglevel = 3

        self.last_10_msg_time = 0
        self.suppress_tx_until = 0

        self.firstsend = 1

        self.frontidx = 0

    def is_old_idx(self, now, last):
        ret = 0

        diff = self.get_idx_diff(now, last)
        if diff < self.valid_idx_diff:
            if now <= last:
                ret = 1
        else:
            if last <= now:
                ret = 1
        return ret

    def txmsgbuf_check_timeout(self):
        dellist = []
        for k, v in self.txmsg_recordbuf:
            if v.created + self.txbuf_timeout_msec < time_ms():
                dellist.append(k)

        for e in dellist:
            self.txmsg_recordbuf.pop(e)

    def txmsg_record(self, data: MsgWindowPkt):
        if data.idx in self.txmsg_recordbuf:
            self.mw_debug(f'Msg {data.idx} is already in buffer')
        else:
            self.txmsg_recordbuf[data.idx] = MsgElem(data)

        if len(self.txmsg_recordbuf) > 1000:
            self.txmsgbuf_check_timeout()

    # Set len and checksum && sendto
    def send_ctrl_packet(self, pkt: MsgWindowPkt):
        pkt.len = len(pkt.msg) + MsgWindowPkt.hdrsz
        pkt.checksum = 0
        chksum = MsgWindow.calc_checksum(pkt.pack())
        pkt.checksum = chksum
        self.sendpkt(pkt)

    def msgwdw_txmsg_internal(self, msg, retransmit_idx):
        pkt = MsgWindowPkt()
        pkt.msg = msg

        if len(msg) > self.max_msglen:
            self.mw_debug(
                3, f'MsgWindow sendlen error{self.max_msglen}<{len(msg)}')
        else:
            if self.firstsend == 1:
                pkt.ctrl = MsgWindow.MSGWINDOW_FIRSTMSG
                pkt.idx = self.sendidx
                self.sendidx = self.get_next_idx(self.sendidx)
                self.firstsend = 0
                self.mw_debug(4, f'Tx first pkt idx {pkt.idx}')
            elif retransmit_idx >= 0:
                pkt.ctrl = MsgWindow.MSGWINDOW_RETRANSMIT
                pkt.idx = retransmit_idx
                self.mw_debug(5, f'Tx retransmit idx {pkt.idx}')
            else:
                pkt.ctrl = MsgWindow.MSGWINDOW_MSG
                pkt.idx = self.sendidx
                self.sendidx = self.get_next_idx(self.sendidx)

        packed = pkt.pack()
        if retransmit_idx < 0:
            self.txmsg_record(packed)
        self.send_ctrl_packet(pkt)

    def do_ratelimit(self):
        currtime = time_ms()
        if self.sendidx % 10 == 0:
            interval = currtime - self.last_10_msg_time
            if interval < self.txratelimit_10_msg_ms:
                self.suppress_tx_until = currtime
                self.suppress_tx_until += self.txratelimit_10_msg_ms - interval
        self.last_10_msg_time = currtime

    def check_rxbuf_timeout(self):
        dellist = []
        for idx, rxmsg in self.rxmsgbuf.items():
            if self.rxbuf_timeout_msec <= time_ms() - rxmsg.created:
                self.mw_debug("Rxbuf entry idx {idx} timeouted")
                dellist.append(idx)

        for idx in dellist:
            del self.rxmsgbuf[idx]

    def msgwdw_txmsg(self, msg):
        self.check_nack_time()
        if time_ms < self.suppress_tx_until:
            return -1
        else:
            self.do_ratelimit()
            self.msgwdw_txmsg_internal(msg, -1)
            return 1

    def rxmsg_dequeue(self, idx):
        return self.rxmsgbuf.get(idx, None)

    def rxmsg_enqueue(self, data: MsgWindowPkt):
        self.rxmsgbuf[data.idx] = data

    def send_buffered(self):
        while True:
            elem: MsgWindowPkt = self.rxmsg_dequeue(
                self.get_next_idx(self.recvidx))
            if elem != None:
                self.recvmsg(elem)

    def recv_msg_now(self, data: MsgWindowPkt):
        self.recvmsg(data)
        self.send_buffered()

    def retransmit_nack(self):
        for k, v in self.nack_list.items():
            if v.last_send + self.nack_interval_msec < time_ms():
                pkt = MsgWindowPkt()
                pkt.idx = k
                pkt.ctrl = MsgWindow.MSGWINDOW_NACK
                self.send_ctrl_packet(pkt)

                v.last_send = time_ms()

    def remove_nack_elem(self, idx):
        ne = self.nack_list.pop(idx, None)
        if ne == None:
            self.mw_debug(f'idx {idx} remove fail')

    def check_rxbuf_timeout(self):
        dellist = []
        for k, v in self.rxmsgbuf:
            if self.rxbuf_timeout_msec <= time_ms() - v.created:
                self.mw_debug(f'Rxbuf entry idx {k} timeouted')
                dellist.append(k)

        for e in dellist:
            self.rxmsgbuf.pop(e)

    def check_nack_time(self):
        if time_ms() - self.last_timecheck > 10:
            self.check_rxbuf_timeout()
            self.check_nacklist_timeout()
            self.retransmit_nack()

    def send_nack(self, idx):
        pkt = MsgWindowPkt()
        pkt.idx = idx
        pkt.ctrl = MsgWindow.MSGWINDOW_NACK
        self.send_ctrl_packet(pkt)

    def jumped_idx_recv(self, data: MsgWindowPkt):

        # For all skipped idx...
        for lostidx in range(self.get_next_idx(self.recvidx), data.idx):
            # 1. send nack
            self.send_nack(lostidx)
            # 2. add to nacklist
            if not lostidx in self.nack_list:
                self.nack_list[lostidx] = NackElem(lostidx)
                self.mw_debug(f'Add nacklist idx {lostidx}')
            else:
                self.mw_debug(f'Nacklist idx {lostidx} is already exists')

        # Buffer message
        if not data.idx in self.rxmsgbuf:
            self.rxmsg_enqueue(data)
            self.mw_debug(f'Msgidx {data.idx} buffered')
        else:
            self.mw_debug(f'Already buffered idx {data.idx}')

    def recv_msg(self, data: MsgWindowPkt):
        expected = self.get_next_idx(self.recvidx)
        if self.valid_recvidx == 1 and data.idx != expected:
            self.invalid_idx_recv(data)
        else:
            self.recvidx = data.idx
            self.valid_recvidx = 1
            self.recv_msg_now(data)

    def old_idx_recv(self, data: MsgWindowPkt):
        if data.idx in self.nack_list:
            self.mw_debug(f'Expected retransmit but no flag(idx : {data.idx}')
            data.ctrl = self.MSGWINDOW_RETRANSMIT
            self.remove_nack_elem(self, data.idx)

            self.recv_msg(data)
        else:
            self.mw_debug(
                f'Duplicated message expected, Drop.(idx {data.idx})')

    def invalid_idx_recv(self, data: MsgWindowPkt):
        diff = MsgWindow.get_idx_diff(data.idx, self.recvidx)
        if diff > self.valid_idx_diff:
            self.mw_debug(
                f'Recv insane idx... reset recvvidx to {self.recvidx}')
            self.nack_list = {}
            self.rxmsgbuf = {}
            self.recvidx = data.idx
            self.valid_recvidx = 1

            self.recv_msg_now(data)
        elif self.is_old_idx(data.idx, self.recvidx):
            self.mw_debug(
                f'Recv old idx(expected {self.get_next_idx(data.idx)} recv {self.recvidx})')
            self.old_idx_recv(data)
        else:
            self.mw_debug(f'Recv jumped idx' +
                          f'expected : {self.get_next_idx(self.recvidx)}' +
                          f'recv : {data.idx}')

    def check_nacklist_timeout(self):
        dellist = []
        for k, v in self.nack_list.items():
            if self.nack_timeout_msec <= time_ms() - v.created:
                self.mw_debug(f'NACK entry idx {k} timeouted')
                if k > self.recvidx:
                    self.recvidx = k

                dellist.append(k)

        for idx in dellist:
            self.nack_list.pop(idx)

    def retransmit_msg(self, idx):
        if idx in self.txmsg_recordbuf:
            self.mw_debug(f'Msgidx {idx} retransmit', idx)
            elem: MsgElem = self.txmsg_recordbuf[idx]
            self.msgwdw_txmsg_internal(elem.pkt.msg, elem.pkt.idx)
        else:
            self.mw_debug(f'Msgidx {idx} retransmit fail(no such entry)')
            msg = MsgWindowPkt()
            msg.ctrl = self.MSGWINDOW_NOELEM
            msg.idx = idx
            self.send_ctrl_packet(msg)

    def is_pkt_ok(self, data: MsgWindowPkt):
        res = 1

        checksum = data.checksum
        data.checksum = 0
        calcd = self.calc_checksum(data.pack())

        if checksum != calcd:
            self.mw_debug(f'MALFORMED PACKET(checksum {checksum} != {calcd})')
            res = 0

        return res

    SUPPRESS_TX_TIME_MS = 5000

    def suppress_tx(self):
        self.mw_log('IO fail detected... Suppress tx')
        self.suppress_tx_until = time_ms() + self.SUPPRESS_TX_TIME_MS

    HEARTBEAT_SEND_INTERVAL_MS = 100
    HEARTBEAT_DROP_ASSUME_TIME = 150

    def send_heartbeat(self):
        msg = MsgWindowPkt()
        msg.ctrl = self.MSGWINDOW_HEARTBEAT
        self.send_ctrl_packet(msg)
        self.last_heartbeat_send = time_ms()

    def check_heartbeat(self):
        currtime = time_ms()

        if self.last_heartbeat_send + self.HEARTBEAT_SEND_INTERVAL_MS < currtime:
            self.send_heartbeat()

        if self.last_heartbeat_recv + self.HEARTBEAT_DROP_ASSUME_TIME < currtime:
            self.last_heartbeat_recv = currtime
            self.suppress_tx_until = time_ms() + self.HEARTBEAT_DROP_ASSUME_TIME

    def msgwdw_work(self):
        self.check_nack_time()
        self.check_heartbeat()

    def send_resolve(self):
        msg = MsgWindowPkt()
        msg.ctrl = self.MSGWINDOW_RESOLVED
        self.send_ctrl_packet(msg)

    def check_resolve(self):
        if not self.nack_list and not self.rxmsgbuf:
            self.send_resolve()

    def msgwdw_inject_rxpacket(self, data):
        pkt = MsgWindowPkt()
        pkt.unpack(data)

        if self.is_pkt_ok(pkt):
            if pkt.ctrl == self.MSGWINDOW_FIRSTMSG:
                self.mw_debug('Firstmsg recved.. reset nacklist')
                if not self.is_old_idx(pkt.idx, self.recvidx):
                    self.frontidx = pkt.idx
                self.nack_list = {}
                self.recv_msg(pkt)
            elif pkt.ctrl == self.MSGWINDOW_MSG:
                if not self.is_old_idx(pkt.idx, self.recvidx):
                    self.frontidx = pkt.idx
                self.remove_nack_elem(pkt.idx)
                self.recv_msg(pkt)
            elif pkt.ctrl == self.MSGWINDOW_RETRANSMIT:
                self.mw_debug(f'Retransmitted message idx {pkt.idx} recvd')
                self.remove_nack_elem(pkt.idx)
                self.recv_msg(pkt)
                self.check_resolve()
            elif pkt.ctrl == self.MSGWINDOW_NACK:
                self.suppress_tx()
                self.retransmit_msg(pkt.idx)
            elif pkt.ctrl == self.MSGWINDOW_NOELEM:
                self.mw_debug(f'Sender response no element idx {pkt.idx}')
                if not self.is_old_idx(pkt.idx, self.recvidx):
                    self.recvidx = pkt.idx
                    self.send_buffered()
                elif not self.is_old_idx(pkt.idx, self.frontidx):
                    self.mw_debug(f'Insane message noelem..' +
                                  f' front {self.frontidx}, reported {pkt.idx}')
            elif pkt.ctrl == self.MSGWINDOW_HEARTBEAT:
                self.last_heartbeat_recv = time_ms()
            elif pkt.ctrl == self.MSGWINDOW_RESOLVED:
                self.mw_debug('Receiver response congestion resolved')
                self.suppress_tx_until = time_ms()
            else:
                self.mw_debug(f'Unavailable ctrl code {pkt.idx}')
