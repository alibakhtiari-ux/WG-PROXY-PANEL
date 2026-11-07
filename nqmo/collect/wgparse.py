"""Fixed-offset parsers for the snaplen-truncated headers the capture layer
delivers. Every function bounds-checks and returns None on anything short or
malformed — a hostile packet can make a parser return None, never raise.

Kept fields are exactly what the design needs (02 §C3); in particular parse_syn
returns only (src, mss): the inner destination is read past, never returned.
"""
import socket
import struct

WG_INIT, WG_RESP, WG_COOKIE, WG_DATA = 1, 2, 3, 4
WG_OVERHEAD_V4 = 60          # IPv4 20 + UDP 8 + data header 16 + Poly1305 tag 16

_IP = struct.Struct("!BBHHHBBH4s4s")       # 20 bytes
_UDP = struct.Struct("!HHHH")


def _ipv4(buf):
    if len(buf) < 20:
        return None
    vihl, _tos, tot_len, ident, frag, _ttl, proto, _csum, src, dst = _IP.unpack_from(buf, 0)
    if vihl != 0x45:                        # IPv4 with IHL=5 only (filters enforce too)
        return None
    return {
        "tot_len": tot_len, "id": ident, "df": bool(frag & 0x4000),
        "mf": bool(frag & 0x2000), "off": (frag & 0x1FFF) * 8, "proto": proto,
        "src": socket.inet_ntoa(src), "dst": socket.inet_ntoa(dst),
    }


def parse_wg(buf):
    """S1/S4 frame → dict or None.

    Indices are returned as the 4 raw bytes (wire order). Pairing compares raw
    bytes on both sides, so no endianness conversion can go wrong.
    """
    ip = _ipv4(buf)
    if ip is None or ip["proto"] != 17 or ip["off"] != 0 or len(buf) < 28 + 4:
        return None
    sport, dport, ulen, _ = _UDP.unpack_from(buf, 20)
    wg = buf[28:]
    mtype = wg[0]
    if wg[1:4] != b"\x00\x00\x00":
        return None
    out = {"ip": ip, "sport": sport, "dport": dport, "udp_len": ulen,
           "type": mtype}
    if mtype == WG_INIT:
        if ulen != 156 or len(wg) < 8:
            return None
        out["sender"] = bytes(wg[4:8])
    elif mtype == WG_RESP:
        if ulen != 100 or len(wg) < 12:
            return None
        out["sender"] = bytes(wg[4:8])
        out["receiver"] = bytes(wg[8:12])
    elif mtype == WG_COOKIE:
        if ulen != 72 or len(wg) < 8:
            return None
        out["receiver"] = bytes(wg[4:8])
    elif mtype == WG_DATA:
        if len(wg) < 16 or ulen < 8 + 32:
            return None
        out["receiver"] = bytes(wg[4:8])
        out["counter"] = struct.unpack_from("<Q", wg, 8)[0]
    else:
        return None
    return out


def parse_first_frag(buf):
    """S2 frame → {src,dst,id,F,O,sport} or None. O = original datagram size."""
    ip = _ipv4(buf)
    if (ip is None or ip["proto"] != 17 or not ip["mf"] or ip["off"] != 0
            or len(buf) < 28):
        return None
    sport, _dport, ulen, _ = _UDP.unpack_from(buf, 20)
    return {"src": ip["src"], "dst": ip["dst"], "id": ip["id"],
            "F": ip["tot_len"], "O": ulen + 20, "sport": sport,
            "payload": ip["tot_len"] - 20}


def parse_tail_frag(buf):
    """S3 frame → {src,dst,id,off,len,mf} or None (payload bytes covered)."""
    ip = _ipv4(buf)
    if ip is None or ip["proto"] != 17 or ip["off"] == 0:
        return None
    return {"src": ip["src"], "dst": ip["dst"], "id": ip["id"],
            "off": ip["off"], "len": ip["tot_len"] - 20, "mf": ip["mf"]}


def parse_syn(buf):
    """S5 frame → (src, mss|None) or None. The destination is never returned."""
    ip = _ipv4(buf)
    if ip is None or ip["proto"] != 6 or ip["off"] != 0 or len(buf) < 40:
        return None
    flags = buf[33]
    if flags & 0x12 != 0x02:
        return None
    doff = (buf[32] >> 4) * 4
    if doff < 20:
        return None
    end = min(len(buf), 20 + doff)
    i = 40
    mss = None
    while i < end:
        kind = buf[i]
        if kind == 0:                    # end of options
            break
        if kind == 1:                    # NOP
            i += 1
            continue
        if i + 1 >= end:
            break
        ln = buf[i + 1]
        if ln < 2 or i + ln > end:
            break
        if kind == 2 and ln == 4:
            mss = struct.unpack_from("!H", buf, i + 2)[0]
            break
        i += ln
    return ip["src"], mss
