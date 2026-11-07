"""Offline IPv4 → ASN lookup (C7). Never downloads anything.

Input: an iptoasn-style TSV placed by the operator (gamma D5, with approval):
    range_start  range_end  AS_number  country_code  AS_description
Ranges must be sorted and non-overlapping; rows with AS 0 ("Not routed") are
kept as gaps. Storage is three array('I') plus a deduplicated name table, so
~600k ranges cost a few MB, not the ~40 MB of Python int lists.

Private/reserved addresses never get an ASN, whatever the file says.
"""
import array
import bisect
import hashlib
import ipaddress
import os
import time

STALE_DAYS = 90


class AsnError(ValueError):
    pass


class AsnDb:
    def __init__(self, starts, ends, asns, cc_idx, names, ccs, sha, mtime):
        self.starts = starts
        self.ends = ends
        self.asns = asns
        self.cc_idx = cc_idx
        self.names = names            # asn → name
        self.ccs = ccs                # index → country code
        self.sha = sha
        self.mtime = mtime

    @property
    def size(self):
        return len(self.starts)

    def stale(self, now=None):
        return ((time.time() if now is None else now) - self.mtime) > STALE_DAYS * 86400

    def lookup(self, ip):
        """→ (asn, name, country) or None."""
        try:
            a = ipaddress.IPv4Address(ip)
        except ValueError:
            return None
        if not a.is_global:
            return None
        v = int(a)
        i = bisect.bisect_right(self.starts, v) - 1
        if i < 0 or v > self.ends[i]:
            return None
        asn = self.asns[i]
        if asn == 0:
            return None
        return asn, self.names.get(asn, ""), self.ccs[self.cc_idx[i]]


def _ip(tok):
    try:
        return int(ipaddress.IPv4Address(tok))
    except ValueError:
        raise AsnError("bad address %r" % tok[:40])


def load(path):
    st = os.stat(path)
    h = hashlib.sha256()
    starts, ends, asns, cc_idx = (array.array("I") for _ in range(4))
    names, ccs, cc_pos = {}, [], {}
    prev_end = -1
    with open(path, "rb") as f:
        for lineno, raw in enumerate(f, 1):
            h.update(raw)
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                raise AsnError("line %d: expected ≥4 tab-separated fields" % lineno)
            s, e = _ip(parts[0]), _ip(parts[1])
            try:
                asn = int(parts[2])
            except ValueError:
                raise AsnError("line %d: bad AS number" % lineno)
            if e < s or s <= prev_end:
                raise AsnError("line %d: ranges must be sorted and non-overlapping" % lineno)
            prev_end = e
            cc = parts[3].strip()[:2] or "??"
            if cc not in cc_pos:
                cc_pos[cc] = len(ccs)
                ccs.append(cc)
            starts.append(s)
            ends.append(e)
            asns.append(asn)
            cc_idx.append(cc_pos[cc])
            if asn and len(parts) > 4 and asn not in names:
                names[asn] = parts[4].strip()[:80]
    if not starts:
        raise AsnError("empty ASN file")
    return AsnDb(starts, ends, asns, cc_idx, names, ccs, h.hexdigest()[:16], st.st_mtime)


def load_dir(d):
    """The newest *.tsv in d, or None when the directory has none."""
    try:
        files = [os.path.join(d, n) for n in os.listdir(d) if n.endswith(".tsv")]
    except FileNotFoundError:
        return None
    if not files:
        return None
    return load(max(files, key=os.path.getmtime))
