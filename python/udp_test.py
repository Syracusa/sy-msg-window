from msgwindow import MsgWindow, MsgWindowPkt
from threading import Thread
import sys
import socket
import struct
import random
import time


UDPTEST_SERVERPORT = 41122
UDPTEST_CLIENTPORT = 41123

UDPTEST_SERVERIP = '127.0.0.1'
UDPTEST_CLIENTIP = '127.0.0.1'

UDPTEST_SERVERADDR = (UDPTEST_SERVERIP, UDPTEST_SERVERPORT)
UDPTEST_CLIENTADDR = (UDPTEST_CLIENTIP, UDPTEST_CLIENTPORT)

RECVBUF_SIZE = 5000

# ==================================================================================


class SimMsg:
    def __init__(self):
        self.len = 0
        self.seq = 0
        self.payload = None

    def unpack(self, bin):
        self.len, self.seq, self.payload = struct.unpack(
            f'=HH{len(bin) - 4}s', bin)

    def pack(self):
        bin = struct.pack(f'=HH{len(self.payload)}s',
                          self.len, self.seq, self.payload)
        return bin


class DummySendSession:
    def __init__(self):
        self.sendidx = 0
        self.lastsend = time.time()
        self.sendinterval = 0

    def send_dummypkt(self, window: MsgWindow):
        if (self.sendidx % 1000 == 0):
            print(f'Trysend idx {self.sendidx + 1}')
        msg = SimMsg()
        msg.seq = (self.sendidx + 1) % 65536
        msg.len = random.randrange(5, 4000)
        rbyte = random.randrange(0, 256)
        msg.payload = bytearray([rbyte] * msg.len)
        self.sendidx = (self.sendidx + 1) % 65536

        while True:
            txres = window.msgwdw_txmsg(msg.pack())
            if txres == 1:
                break
            else:
                print(f'Txmsg seq {msg.seq} transmit fail')
                time.sleep(0.001)


    def send_dummypkt_checktime(self, window: MsgWindow):
        currtime = time.time()
        if self.lastsend + self.sendinterval < currtime:
            self.send_dummypkt(window)
            self.lastsend = currtime

class DummyRecvSession:
    def __init__(self):
        self.recvseq = 0

    def check_dummy(self, msg: SimMsg):

        if msg.seq % 1000 == 0:
            print(f'msg seq {msg.seq} recvd')

        if msg.seq != (self.recvseq + 1) % 65536:
            print(f'!!!!!Server recvseq error! ' +
                  f'recv:{msg.seq} expected:{(self.recvseq + 1) % 65536}')
        self.recvseq = msg.seq

        if msg.len != len(msg.payload):
            print(f'!!!!!Server recvlen error! {msg.len} {len(msg.payload)}')

# ==============================================================================


recvsock = None
sendsock = None
is_client = None
sendSession = DummySendSession()
recvSession = DummyRecvSession()

# This function is send to msgwindow


def send_testsock(pkt: bytes):
    # do udpsend
    if is_client:  # client -> server send
        dest = UDPTEST_SERVERADDR
    else:  # server -> client send
        dest = UDPTEST_CLIENTADDR

    # Simulate packet drop
    DO_DROP = 1
    DROPRATE = 20
    if DO_DROP:
        if 1 == random.randrange(DROPRATE) and len(pkt) > 10:
            print('Simulate drop!')
        else:
            sendsock.sendto(pkt, dest)
    else:
        sendsock.sendto(pkt, dest)
# We should recv packet and inject to msgwindow


def recv_testsock(window: MsgWindow):
    # print('recvroutine..')
    data, addr = recvsock.recvfrom(RECVBUF_SIZE)

    window.msgwdw_inject_rxpacket(data)


# This function is send to msgwindow
def recvfrom_window(pkt: bytes):
    msg = SimMsg()
    msg.unpack(pkt)
    recvSession.check_dummy(msg)


def send_routine(window: MsgWindow):
    while True:
        if is_client:
            sendSession.send_dummypkt_checktime(window)

        time.sleep(0.0001)
        window.msgwdw_work()


def do_client():
    global sendsock
    global recvsock
    global is_client

    is_client = 1
    # Create window
    window = MsgWindow(1000, 4092, send_testsock, recvfrom_window, 'client')

    # Init socket(Divide recv and send socket to multiplexing io)
    sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recvsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recvsock.bind(UDPTEST_CLIENTADDR)

    # Send thread
    t = Thread(target=send_routine, args=[window])
    t.start()

    # Recv Loop
    while True:
        recv_testsock(window)


def do_server():
    global sendsock
    global recvsock
    global is_client

    is_client = 0
    # Create window
    window = MsgWindow(1000, 4092, send_testsock, recvfrom_window, 'server')

    # Init socket(Divide recv and send socket to multiplexing io)
    sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recvsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recvsock.bind(UDPTEST_SERVERADDR)

    # Send thread
    t = Thread(target=send_routine, args=[window])
    t.start()

    # Recv Loop
    while True:
        recv_testsock(window)


if __name__ == "__main__":
    if sys.argv[1][0] == 'c':
        print('Start as client')
        do_client()
    else:
        print('Start as server')
        do_server()
