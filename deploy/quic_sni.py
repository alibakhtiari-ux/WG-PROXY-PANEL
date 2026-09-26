#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""استخراجِ SNI از یک بستهٔ QUIC Initial — پایتونِ خالصِ stdlib.

چرا لازم است: در جراحیِ SNI-splitِ TCP، QUIC (UDP/443) به مقصدهای AI رد
(REJECT) می‌شد تا مرورگر به TCP برگردد؛ ولی چون /24های گوگل اشتراکی‌اند، این
یعنی QUICِ یوتیوب/سرچِ کولترال هم بی‌جهت رد می‌شد. برای «معاف‌کردنِ کولترال»
بدونِ شکستنِ AI باید QUIC را هم بر پایهٔ SNI تفکیک کرد — و SNI درونِ CRYPTO
frameِ رمزنگاری‌شدهٔ QUIC Initial است.

رمزنگاریِ QUIC Initial (RFC 9001) با کلیدهایی است که فقط از Destination
Connection ID و یک saltِ ثابتِ عمومی مشتق می‌شوند — پس هر ناظری (از جمله ما)
می‌تواند Initial را بخواند (این عمداً چنین است تا میان‌افزارها کار کنند).
مسیر: HKDF (SHA-256، از hashlib) → کلیدِ AES-128 → رفعِ header protection
(AES-ECB) → رمزگشاییِ AES-128-GCM → بازآراییِ CRYPTO → ClientHello → SNI.

AES-128 در stdlib نیست؛ اینجا پیاده‌سازیِ خالص (فقط رمزگذاریِ بلوک، که هم
برای ECBِ header protection و هم برای CTR/GHASHِ GCM کافی است) آمده و با
وکتورهای NIST و RFC 9001 تست می‌شود.
"""

import hashlib
import hmac
import struct

# ---------------------------------------------------------------------------
# AES-128 (فقط رمزگذاریِ بلوک — برای HP/ECB و CTR/GHASHِ GCM کافی است)
# ---------------------------------------------------------------------------
_SBOX = (
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
)
_RCON = (0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36)


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff


def _key_expansion(key):
    """۱۱ round key (هر کدام ۱۶ بایت) برای AES-128."""
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [_SBOX[b] for b in t]              # SubWord
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    keys = []
    for r in range(11):
        rk = bytearray()
        for c in range(4):
            rk += bytes(w[r * 4 + c])
        keys.append(bytes(rk))
    return keys


def _aes_encrypt_block(rkeys, block):
    s = list(block)
    # افزودنِ کلیدِ اولیه
    for i in range(16):
        s[i] ^= rkeys[0][i]
    for rnd in range(1, 10):
        s = [_SBOX[b] for b in s]                  # SubBytes
        # ShiftRows (چیدمانِ ستون-محور: index = row + 4*col)
        s = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ]
        # MixColumns
        ns = [0] * 16
        for c in range(4):
            a0, a1, a2, a3 = s[4 * c:4 * c + 4]
            ns[4 * c + 0] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
            ns[4 * c + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
            ns[4 * c + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
            ns[4 * c + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)
        s = ns
        for i in range(16):
            s[i] ^= rkeys[rnd][i]
    # دورِ آخر (بدونِ MixColumns)
    s = [_SBOX[b] for b in s]
    s = [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]
    for i in range(16):
        s[i] ^= rkeys[10][i]
    return bytes(s)


class AES128:
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("AES-128 نیازمندِ کلیدِ ۱۶بایتی")
        self._rk = _key_expansion(key)

    def encrypt_block(self, block):
        return _aes_encrypt_block(self._rk, block)


# ---------------------------------------------------------------------------
# GCM (فقط رمزگشایی — که به رمزگذاریِ بلوک نیاز دارد)
# ---------------------------------------------------------------------------
def _ghash_mul(x, y):
    """ضربِ دو عنصرِ GF(2^128) طبقِ کنوانسیونِ GCM."""
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ (0xe1 << 120)
        else:
            v >>= 1
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        if len(blk) < 16:
            blk = blk + b"\x00" * (16 - len(blk))
        y ^= int.from_bytes(blk, "big")
        y = _ghash_mul(y, h)
    return y


def aes128_gcm_decrypt(key, iv, ciphertext, aad, tag):
    """رمزگشایی + بررسیِ tag. اگر tag نخورد None برمی‌گرداند."""
    aes = AES128(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    # J0 برای IVِ ۱۲بایتی = IV || 0x00000001
    if len(iv) == 12:
        j0 = iv + b"\x00\x00\x00\x01"
    else:
        s = (16 - len(iv) % 16) % 16
        padded = iv + b"\x00" * s + b"\x00" * 8 + struct.pack(">Q", len(iv) * 8)
        j0 = _ghash(h, padded).to_bytes(16, "big")
    # بررسیِ tag
    lens = struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)
    ghash_in = aad + b"\x00" * ((-len(aad)) % 16) \
        + ciphertext + b"\x00" * ((-len(ciphertext)) % 16) + lens
    s_val = _ghash(h, ghash_in)
    ej0 = aes.encrypt_block(j0)
    calc_tag = (s_val ^ int.from_bytes(ej0, "big")).to_bytes(16, "big")
    if not hmac.compare_digest(calc_tag, bytes(tag)):
        return None
    # رمزگشایی با CTR (شمارنده از J0+1)
    out = bytearray()
    ctr = int.from_bytes(j0, "big")
    for i in range(0, len(ciphertext), 16):
        ctr = (ctr & ~0xffffffff) | ((ctr + 1) & 0xffffffff)
        ks = aes.encrypt_block(ctr.to_bytes(16, "big"))
        blk = ciphertext[i:i + 16]
        out += bytes(a ^ b for a, b in zip(blk, ks))
    return bytes(out)


# ---------------------------------------------------------------------------
# HKDF (RFC 5869) + HKDF-Expand-Label (RFC 8446/TLS)
# ---------------------------------------------------------------------------
def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out = b""
    t = b""
    i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def hkdf_expand_label(secret, label, context, length):
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full \
        + bytes([len(context)]) + context
    return hkdf_expand(secret, info, length)


# ---------------------------------------------------------------------------
# QUIC Initial (RFC 9000/9001، فقط نسخهٔ ۱)
# ---------------------------------------------------------------------------
QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _varint(buf, off):
    """خواندنِ عددِ variable-length طبقِ QUIC. (مقدار، آفستِ جدید)"""
    if off >= len(buf):
        raise ValueError("varint کوتاه")
    b0 = buf[off]
    ln = 1 << (b0 >> 6)
    if off + ln > len(buf):
        raise ValueError("varint سرریز")
    val = b0 & 0x3f
    for i in range(1, ln):
        val = (val << 8) | buf[off + i]
    return val, off + ln


def initial_secrets(dcid):
    """کلید/iv/hpِ سمتِ کلاینت را از DCID مشتق می‌کند."""
    initial_secret = hkdf_extract(QUIC_V1_SALT, dcid)
    client_secret = hkdf_expand_label(initial_secret, b"client in", b"", 32)
    key = hkdf_expand_label(client_secret, b"quic key", b"", 16)
    iv = hkdf_expand_label(client_secret, b"quic iv", b"", 12)
    hp = hkdf_expand_label(client_secret, b"quic hp", b"", 16)
    return key, iv, hp


def decrypt_initial(datagram):
    """پیلودِ رمزگشایی‌شدهٔ یک بستهٔ QUIC Initialِ کلاینت را برمی‌گرداند
    (محتوای frameها)، یا None اگر Initial/نسخهٔ ۱ نبود یا رمزگشایی نخورد."""
    try:
        d = datagram
        if len(d) < 7:
            return None
        first = d[0]
        # long header (بیتِ ۰x80) + نسخهٔ ۱ + نوعِ Initial (00 در بیت‌های 4-5)
        if not (first & 0x80):
            return None
        version = int.from_bytes(d[1:5], "big")
        if version != 1:
            return None
        if (first & 0x30) != 0x00:               # نوعِ بسته: Initial
            return None
        off = 5
        dcid_len = d[off]; off += 1
        dcid = d[off:off + dcid_len]; off += dcid_len
        scid_len = d[off]; off += 1
        off += scid_len                          # SCID (نادیده)
        token_len, off = _varint(d, off)
        off += token_len                         # token (نادیده)
        length, off = _varint(d, off)            # طولِ (packet number + payload)
        pn_offset = off
        if pn_offset + length > len(d):
            return None
        key, iv, hp = initial_secrets(dcid)
        # ---- رفعِ header protection ----
        # نمونه = ۱۶ بایت از offsetِ pn_offset+4
        sample_off = pn_offset + 4
        sample = d[sample_off:sample_off + 16]
        if len(sample) < 16:
            return None
        mask = AES128(hp).encrypt_block(sample)
        first_unmasked = first ^ (mask[0] & 0x0f)
        pn_len = (first_unmasked & 0x03) + 1
        hdr = bytearray(d[:pn_offset + pn_len])
        hdr[0] = first_unmasked
        pn_bytes = bytearray(d[pn_offset:pn_offset + pn_len])
        for i in range(pn_len):
            pn_bytes[i] ^= mask[1 + i]
        packet_number = int.from_bytes(pn_bytes, "big")
        hdr[pn_offset:pn_offset + pn_len] = pn_bytes
        # ---- رمزگشاییِ payload (AES-128-GCM) ----
        ct_and_tag = d[pn_offset + pn_len:pn_offset + length]
        if len(ct_and_tag) < 16:
            return None
        ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
        # nonce = iv XOR (packet number، راست‌چین در ۱۲ بایت)
        pn_full = packet_number.to_bytes(12, "big")
        nonce = bytes(a ^ b for a, b in zip(iv, pn_full))
        return aes128_gcm_decrypt(key, nonce, ciphertext, bytes(hdr), tag)
    except (ValueError, IndexError):
        return None


# سقفِ ردیفِ نگاشتِ CRYPTO در **یک** دیتاگرام. ورودی UDPِ احراز هویت‌نشده
# است: فرستنده می‌تواند صدها frameِ خرد با offsetهای پراکنده بفرستد.
_CRYPTO_MAX_FRAMES = 256


def crypto_from_datagram(datagram):
    """CRYPTO frameهای یک دیتاگرام: `{offset: bytes}`، یا `None`.

    تفاوتِ `None` با نگاشتِ خالی معنادار است: `None` یعنی «Initialِ
    رمزگشایی‌پذیر نبود» (پکتِ short-header، نسخه‌ی دیگر، DCIDِ عوض‌شده)،
    نگاشتِ خالی یعنی «Initial بود ولی CRYPTO نداشت» (فقط ACK/PADDING).
    """
    payload = decrypt_initial(datagram)
    if payload is None:
        return None
    crypto = {}   # offset -> data
    i = 0
    n = len(payload)
    try:
        while i < n:
            ft = payload[i]
            if ft == 0x00:                       # PADDING
                i += 1
                continue
            if ft == 0x01:                       # PING
                i += 1
                continue
            if ft == 0x06:                       # CRYPTO
                i += 1
                offset, i = _varint(payload, i)
                clen, i = _varint(payload, i)
                if clen:                         # frameِ صفر-طول چیزی ندارد
                    if len(crypto) >= _CRYPTO_MAX_FRAMES:
                        break
                    crypto[offset] = payload[i:i + clen]
                i += clen
                continue
            # هر frameِ دیگری در Initial نادر است؛ ادامه بی‌معنا و ناامن است
            break
    except (ValueError, IndexError):
        pass
    return crypto


def join_crypto(crypto):
    """پیوسته از offsetِ صفر به هم می‌چسباند؛ حفره که رسید می‌ایستد."""
    data = b""
    expected = 0
    for off in sorted(crypto):
        if off != expected:
            break
        data += crypto[off]
        expected += len(crypto[off])
    return data


def sni_from_crypto(crypto, sni_parser):
    """SNI را از نگاشتِ (احتمالاً **انباشته‌ی**) CRYPTO درمی‌آورد.

    کارِ تازه‌اش تفکیکِ «هنوز کامل نشده» از «SNI ندارد» است — که پیش از این
    ممکن نبود: رکوردِ TLSِ جعلی با طولِ همان بایت‌های موجود ساخته می‌شود، پس
    از دیدِ پارسر همیشه خودسازگار است و ClientHelloِ بریده را «کاملِ بدونِ
    SNI» می‌بیند. معیارِ کامل بودن از خودِ هدرِ handshake می‌آید:
    `type(1) + length(3)`.

    اهمیتش نظری نیست: با `X25519MLKEM768` که در کروم و فایرفاکسِ امروز
    پیش‌فرض است، ClientHello از سقفِ ~۱۲۰۰ بایتیِ پیلودِ Initial رد می‌شود و
    در **دو** پکت می‌آید — حالتِ عادی، نه استثنا.

    خروجی: ("ok", host|None) | ("need_more", None) | ("bad", None)
    """
    if not crypto:
        return ("bad", None)
    data = join_crypto(crypto)
    if not data:
        return ("need_more", None)     # هنوز به offsetِ صفر نرسیده‌ایم
    if len(data) > 0xFFFF:
        return ("bad", None)           # ClientHelloِ واقعی این‌قدر نیست
    # data خودِ محتوای handshakeِ TLS است (بدونِ رکوردِ TLS record layer)؛
    # پارسرِ splitter رکوردِ 0x16 می‌خواهد پس یک هدرِ رکوردِ جعلی می‌سازیم.
    fake_record = b"\x16\x03\x01" + len(data).to_bytes(2, "big") + data
    st, host = sni_parser(fake_record)
    if st == "ok" and host:
        # SNI پیش از نقطه‌ی برش آمده — نیامدنِ دنباله بی‌اثر است. این شاخه
        # عمدی است: نیمی از ClientHelloهای دوپکتی SNI را در پکتِ اول دارند
        # (کروم ترتیبِ اکستنشن‌ها را می‌چیند) و امروز درست مسیریابی می‌شوند.
        # بی این شاخه، «کامل‌گرایی» همان نیمه را هم به fail-open می‌فرستاد.
        return ("ok", host)
    if len(data) >= 4 and data[0] == 0x01:
        want = 4 + int.from_bytes(data[1:4], "big")
        if len(data) < want:
            return ("need_more", None)
    return (st, host)


def sni_from_initial(datagram, sni_parser):
    """SNI را از یک بستهٔ QUIC Initial درمی‌آورد.

    sni_parser: تابعِ پارسِ ClientHello (همان پارسرِ TCP از splitter؛ تزریق
    می‌شود تا این ماژول مستقل و بی‌وابستگی بماند). CRYPTO frameها را (که ممکن
    است پراکنده باشند) به‌ترتیبِ offset بازمی‌آراید، هدرِ رکوردِ TLS جعلی
    می‌سازد و به پارسر می‌دهد.

    دامنه‌اش **یک دیتاگرام** است. ClientHelloِ پخش‌شده در چند پکتِ Initial را
    فراخوان باید انباشت کند (`crypto_from_datagram` + `sni_from_crypto`) —
    حالتِ جریان عمداً اینجا نیست تا این ماژول بی‌حالت و بی‌وابستگی بماند.

    خروجی: ("ok", host|None) | ("need_more", None) | ("bad", None)
    """
    crypto = crypto_from_datagram(datagram)
    if crypto is None:
        return ("bad", None)
    return sni_from_crypto(crypto, sni_parser)
