"""C3 low-rate streams (S1 S2 S3 S5): receive-only AF_PACKET taps.

Safe construction order (review finding 3): a packet socket created with a
non-zero protocol is hooked to every interface at once, before any filter
exists. So: socket(proto=0) → attach fixed filter → lock it → enable kernel
timestamps → bind(ifname, proto). Nothing is delivered before bind.

S1 binds ETH_P_ALL because outgoing frames reach only ptype_all taps
(dev_queue_xmit_nit); the other streams are inbound-only and bind ETH_P_IP.

This module never sends: tests/test_nqmo.py fails on any .send/.sendto/
.sendmsg call in nqmo/collect/capture.py or ring.py.
"""
import ctypes
import socket
import struct

from . import bpf

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
SOL_PACKET = 263
PACKET_STATISTICS = 6
SO_ATTACH_FILTER = 26
SO_LOCK_FILTER = 44
SO_TIMESTAMPNS = 35          # SO_TIMESTAMPNS_OLD on x86_64 / aarch64
SCM_TIMESTAMPNS = SO_TIMESTAMPNS
PACKET_HOST = 0
PACKET_OUTGOING = 4

# stream → (interface role, bind protocol, program)
STREAMS = {
    "S1": ("wan", ETH_P_ALL, "S1_HANDSHAKE"),
    "S2": ("wan", ETH_P_IP, "S2_FIRST_FRAG"),
    "S3": ("wan", ETH_P_IP, "S3_TAIL_FRAG"),
    "S5": ("user", ETH_P_IP, "S5_SYN"),
}


class CaptureError(RuntimeError):
    pass


def fprog_bytes(insns):
    """struct sock_fprog for setsockopt. Returns (bytes, keepalive buffer)."""
    n = len(insns)
    buf = ctypes.create_string_buffer(8 * n)
    for i, (code, jt, jf, k) in enumerate(insns):
        struct.pack_into("=HBBI", buf, 8 * i, code, jt, jf, k)
    return struct.pack("HL", n, ctypes.addressof(buf)), buf


def open_tap(ifname, bind_proto, program, sock_mod=socket, rcvbuf=None):
    """Create a filtered, locked, timestamping, receive-only packet socket."""
    prog = bpf.PROGRAMS[program]
    s = sock_mod.socket(sock_mod.AF_PACKET, sock_mod.SOCK_DGRAM, 0)
    try:
        fp, keep = fprog_bytes(prog["insns"])
        s.setsockopt(sock_mod.SOL_SOCKET, SO_ATTACH_FILTER, fp)
        del keep                               # kernel copied the program
        s.setsockopt(sock_mod.SOL_SOCKET, SO_LOCK_FILTER, 1)
        s.setsockopt(sock_mod.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        if rcvbuf:
            s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_RCVBUF, rcvbuf)
        s.bind((ifname, bind_proto))
    except Exception:
        s.close()
        raise
    return s


def read_stats(s):
    """(packets, drops) since the previous call — the kernel resets on read."""
    raw = s.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
    return struct.unpack("II", raw)


def recv_one(s, snaplen):
    """→ (ts_float_kernel, pkttype, bytes) ; ts from SCM_TIMESTAMPNS."""
    data, anc, _flags, addr = s.recvmsg(snaplen, socket.CMSG_SPACE(16))
    ts = None
    for level, ctype, cdata in anc:
        if level == socket.SOL_SOCKET and ctype == SCM_TIMESTAMPNS and len(cdata) >= 16:
            sec, nsec = struct.unpack_from("qq", cdata)
            ts = sec + nsec / 1e9
    pkttype = addr[2] if isinstance(addr, tuple) and len(addr) > 2 else None
    return ts, pkttype, data


def check_port(listen_port):
    if listen_port != bpf.PORT:
        raise CaptureError(
            "listen_port %d != compiled BPF port %d; regenerate with "
            "tools/gen_nqmo_bpf.py instead of patching bytecode"
            % (listen_port, bpf.PORT))
