"""C3 high-rate stream S4: PACKET_RX_RING / TPACKET_V3 (mmap).

SO_RCVBUF is not used: each queued clone is charged its full truesize, so a
socket buffer holds only ~100–200 packets (review finding 21). The ring holds
snaplen-sized frames and carries kernel timestamps for free.

Order is the same as capture.open_tap: socket(proto=0) → filter → lock →
PACKET_VERSION → PACKET_RX_RING → mmap → bind(ETH_P_IP). Receive-only.
"""
import mmap
import select
import socket
import struct

from . import bpf
from .capture import ETH_P_IP, SO_ATTACH_FILTER, SO_LOCK_FILTER, SOL_PACKET, fprog_bytes

PACKET_RX_RING = 5
PACKET_VERSION = 10
TPACKET_V3 = 2
TP_STATUS_KERNEL = 0
TP_STATUS_USER = 1
TP_STATUS_LOSING = 1 << 2          # if_packet.h: block closed while tp_drops != 0

# struct tpacket_block_desc { u32 version; u32 offset_to_priv; tpacket_hdr_v1 }
# tpacket_hdr_v1 { u32 block_status; u32 num_pkts; u32 offset_to_first_pkt;
#                  u32 blk_len; u64 seq_num; ts first; ts last }
_BLK = struct.Struct("=IIIIIIQ")              # through seq_num (32 bytes)
# struct tpacket3_hdr { u32 tp_next_offset; u32 tp_sec; u32 tp_nsec;
#   u32 tp_snaplen; u32 tp_len; u32 tp_status; u16 tp_mac; u16 tp_net; ... }
_PKT = struct.Struct("=IIIIIIHH")
_STATUS_OFF = 8                               # offset of block_status in desc


def iter_block(mem, base):
    """Yield (ts, tp_len, frame_bytes) for one *user-owned* block at base.

    tp_len is the original wire length; frame bytes are snaplen-truncated and
    start at the network header (SOCK_DGRAM ⇒ tp_net).
    """
    _ver, _priv, status, num, first, blk_len, _seq = _BLK.unpack_from(mem, base)
    if not status & TP_STATUS_USER:
        return
    off = base + first
    end = base + blk_len
    for _ in range(num):
        if off + _PKT.size > end:
            return                            # malformed: stop, never overrun
        nxt, sec, nsec, snap, tp_len, _st, _mac, net = _PKT.unpack_from(mem, off)
        start = off + net
        if start + snap > end:
            return
        yield sec + nsec / 1e9, tp_len, bytes(mem[start:start + snap])
        if nxt == 0:
            return
        off += nxt


def release_block(mem, base):
    struct.pack_into("=I", mem, base + _STATUS_OFF, TP_STATUS_KERNEL)


class Ring:
    def __init__(self, ifname, block_kb=256, blocks=16, sock_mod=socket,
                 mmap_mod=mmap):
        prog = bpf.PROGRAMS["S4_DATA"]
        self.block_size = block_kb * 1024
        self.blocks = blocks
        frame = 128                           # ≥ TPACKET3 hdr + 44-byte snaplen
        s = sock_mod.socket(sock_mod.AF_PACKET, sock_mod.SOCK_DGRAM, 0)
        try:
            fp, keep = fprog_bytes(prog["insns"])
            s.setsockopt(sock_mod.SOL_SOCKET, SO_ATTACH_FILTER, fp)
            del keep
            s.setsockopt(sock_mod.SOL_SOCKET, SO_LOCK_FILTER, 1)
            s.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V3)
            req = struct.pack("=IIIIIII", self.block_size, blocks, frame,
                              (self.block_size // frame) * blocks,
                              100, 0, 0)       # retire a block after 100 ms
            s.setsockopt(SOL_PACKET, PACKET_RX_RING, req)
            self.mem = mmap_mod.mmap(s.fileno(), self.block_size * blocks,
                                     mmap_mod.MAP_SHARED,
                                     mmap_mod.PROT_READ | mmap_mod.PROT_WRITE)
            s.bind((ifname, ETH_P_IP))
        except Exception:
            s.close()
            raise
        self.sock = s
        self.cur = 0

    def poll(self, timeout=1.0, parse=True):
        """Yield ("gap", drops) / ("frame", (ts, tp_len, bytes)) from every
        ready block, releasing each after reading.

        A block flagged TP_STATUS_LOSING means frames were dropped before it
        closed: the gap is yielded (with PACKET_STATISTICS read — and reset —
        right now) BEFORE any of that block's frames, so no window is judged
        across the hole (review round 2, B2). parse=False releases blocks
        without touching their frames (sampling fast path); it still reports
        gaps so the reducer knows its windows are broken.
        """
        from .capture import read_stats
        select.select([self.sock], [], [], timeout)
        for _ in range(self.blocks):
            base = self.cur * self.block_size
            status = struct.unpack_from("=I", self.mem, base + _STATUS_OFF)[0]
            if not status & TP_STATUS_USER:
                break
            if status & TP_STATUS_LOSING:
                _pk, drops = read_stats(self.sock)
                yield ("gap", max(drops, 1))
            if parse:
                for item in iter_block(self.mem, base):
                    yield ("frame", item)
            release_block(self.mem, base)
            self.cur = (self.cur + 1) % self.blocks

    def close(self):
        try:
            self.mem.close()
        finally:
            self.sock.close()
