
import base64
import math
import numpy as np
from typing import List, Tuple, Sequence

# --------------------------------------------------------------------------
# Low-level utilities
# --------------------------------------------------------------------------
def _dtype_for_bits(bits: int):
    """Smallest unsigned dtype that can hold `bits` bits."""
    if bits <= 8:
        return np.uint8
    elif bits <= 16:
        return np.uint16
    elif bits <= 32:
        return np.uint32
    else:
        return np.uint64


def _pack_bits_vec(
    values: np.ndarray,
    bits: int,
    prefix: Sequence[Tuple[int, int]] | None = None,
) -> bytes:
    values = values.astype(np.uint64, copy=False)
    n = values.size

    assert bits<=12, "This one is bugged for larger bits :/"

    # compute total bits and allocate a byte array padded to 4-byte boundary
    pfx_bits = sum(nb for _, nb in prefix) if prefix else 0
    total_bits = pfx_bits + n * bits
    n_bytes = (total_bits + 7) // 8
    n_bytes_padded = ((n_bytes + 3) // 4) * 4
    out8 = np.zeros(n_bytes_padded, dtype=np.uint8)

    # view as little-endian uint32 for MSB-first math,
    # then byteswap back at the end
    out32_le = out8.view(dtype=np.dtype('<u4'))

    # payload bit positions (after prefix)
    bitpos   = pfx_bits + np.arange(n, dtype=np.uint64) * bits
    word_idx = bitpos >> 5
    bit_off  = (bitpos & 31).astype(np.uint8)

    # values fully within one 32-bit word
    fits = bit_off + bits <= 32
    if np.any(fits):
        shift = 32 - bits - bit_off[fits]
        part  = (values[fits] << shift) & 0xFFFFFFFF
        np.bitwise_or.at(out32_le, word_idx[fits], part.astype(np.uint32))

    # values crossing the 32-bit boundary
    cross = ~fits
    if np.any(cross):
        lo_bits = 32 - bit_off[cross]
        hi_bits = bits - lo_bits

        # low part in this word
        lo_part = (values[cross] >> hi_bits) & ((1 << lo_bits) - 1)
        # lo_part already aligned since lo_bits + start_offset == 32
        np.bitwise_or.at(out32_le, word_idx[cross], lo_part.astype(np.uint32))

        # high part in the next word
        hi_part = values[cross] & ((1 << hi_bits) - 1)
        hi_part <<= (32 - hi_bits)
        np.bitwise_or.at(out32_le, word_idx[cross] + 1, hi_part.astype(np.uint32))

    # byteswap our working LE view back to BE
    out32_le.byteswap(inplace=True)

    # write prefix bits into the first pfx_bits
    if prefix:
        p_val = 0
        for val, nb in prefix:
            if val >= (1 << nb):
                raise ValueError(f"{val} won’t fit in {nb} bits")
            p_val = (p_val << nb) | val

        p_bytes = (pfx_bits + 7) // 8
        shift = 8 * p_bytes - pfx_bits
        p_val <<= shift
        pfx_arr = np.frombuffer(p_val.to_bytes(p_bytes, "big"), dtype=np.uint8)
        out8[:p_bytes] |= pfx_arr

    return out8[:n_bytes].tobytes()

def _pack_bits(
    values: np.ndarray,
    bits_per_val: int,
    prefix: List[Tuple[int, int]] | None = None,
) -> bytes:
    """
    Packs *prefix* bits (list of `(value, n_bits)` tuples) **followed by**
    `values` (each `bits_per_val` wide) into a byte-aligned buffer.
    """
    if bits_per_val <= 12:
        return _pack_bits_vec(values, bits_per_val, prefix)
    
    buf = 0
    buf_bits = 0
    out = bytearray()

    def _write(val: int, n: int):
        nonlocal buf, buf_bits
        buf = (buf << n) | val
        buf_bits += n
        while buf_bits >= 8:
            shift = buf_bits - 8
            out.append((buf >> shift) & 0xFF)
            buf_bits -= 8
            buf &= (1 << buf_bits) - 1 if buf_bits else 0

    # --- prefix -----------------------------------------------------------
    if prefix:
        for val, n in prefix:
            if val >= (1 << n):
                raise ValueError(f"{val} will not fit in {n} bits")
            _write(val, n)

    # --- payload ----------------------------------------------------------
    for v in values:
        _write(int(v), bits_per_val)

    if buf_bits:                                   # tail (pad right with zeros)
        out.append(buf << (8 - buf_bits) & 0xFF)

    return bytes(out)


class _BitReader:
    """MSB-first bit reader for the decoding side."""
    def __init__(self, data: bytes):
        self.stream = int.from_bytes(data, "big")
        self.total = len(data) * 8
        self.pos = 0                               # bits consumed so far

    def read(self, n: int) -> int:
        if self.pos + n > self.total:
            raise ValueError("Ran out of bits")
        shift = self.total - self.pos - n
        val = (self.stream >> shift) & ((1 << n) - 1)
        self.pos += n
        return val


# --------------------------------------------------------------------------
# Public API – new compact header
# --------------------------------------------------------------------------
def ndarray_to_base64(arr: np.ndarray) -> str:
    """
    Encode an unsigned-integer NumPy array with the *compact* header:
        • 5  bits : (bit-width – 2)               -> range 2..33
        • 3  bits : k   where (k+1)*4 is #bits used for the length
        • k*4 bits: length itself (4 .. 32 bits)
        • payload : values, each `bit-width` bits
    The whole stream is byte-aligned and Base-64 encoded.
    """
    flat = np.asarray(arr, dtype=np.uint64).ravel()
    if flat.size == 0:
        raise ValueError("empty array")

    # --- bit-width --------------------------------------------------------
    max_val = int(flat.max())
    bits = max(2, math.ceil(math.log2(max_val + 1)))   # we never store <2 bits
    if bits > 33:
        raise ValueError("bit-width >33 not supported by 5-bit header")
    bits_code = bits - 2                                # 0..31 ➟ store in 5 bits

    # --- length field -----------------------------------------------------
    n = flat.size
    len_needed = max(1, math.ceil(math.log2(n + 1)))    # bits to store n
    length_bits = 4
    while length_bits < len_needed:
        length_bits += 4
    if length_bits > 32:
        raise ValueError("array too long for 32-bit length header")
    length_prefix = length_bits // 4 - 1                # 0..7 ➟ store in 3 bits

    # --- header as "prefix bits" -----------------------------------------
    prefix = [
        (bits_code, 5),             # 5 bits
        (length_prefix, 3),         # 3 bits
        (n, length_bits),           # variable bits (4–32)
    ]

    raw = _pack_bits(flat, bits, prefix=prefix)
    return base64.b64encode(raw).decode("ascii")


def base64_to_ndarray(s: str) -> np.ndarray:
    """
    Reverse of `ndarray_to_base64` – returns a NumPy array whose dtype is the
    narrowest unsigned integer type that fits the stored bit-width.
    """
    data = base64.b64decode(s.encode("ascii"))
    r = _BitReader(data)

    bits_code = r.read(5)
    bits = bits_code + 2                               # restore real bit-width

    length_prefix = r.read(3)
    length_bits = (length_prefix + 1) * 4
    n = r.read(length_bits)

    out = np.empty(n, dtype=_dtype_for_bits(bits))
    for i in range(n):
        out[i] = r.read(bits)

    return out


# ---------------------------------------------------------------------------
# vectorised decoder
# ---------------------------------------------------------------------------
def base64_to_ndarray_vec(s: str) -> np.ndarray:
    """
    Reverse of the compact Base-64 encoder, but **fully vectorised**.
    *Reads*:
        • 5  bits  – (bit-width – 2)
        • 3  bits  – selector for length-field size  (k  ⇒  (k+1)*4 bits)
        • X bits   – length (big-endian, MSB-aligned inside its field)
        • payload  – n values, each `bits` wide, back-to-back
    Returns a NumPy array using the narrowest unsigned dtype that can hold
    `bits` bits (uint8/16/32/64).
    """
    raw = base64.b64decode(s.encode("ascii"))
    if len(raw) < 2:
        raise ValueError("corrupted input – header incomplete")

    # --------------------------------------------------------------------
    # 1.  Extract header fields (cheap bit-twiddling on the first bytes)
    # --------------------------------------------------------------------
    first = raw[0]
    bits_code  = first >> 3               # top 5 bits
    bits       = bits_code + 2            # real bit-width   (2‥33)
    if bits > 33 or bits < 2:
        raise ValueError("invalid bit-width in header")

    # print(f"bits: {bits}")

    len_sel    = first & 0b111            # bottom 3 bits
    len_bits   = (len_sel + 1) * 4        # 4‥32
    hdr_bits   = 8 + len_bits
    len_bytes  = (len_bits + 7) // 8
    # print(f"len_bits: {len_bits}")

    if len(raw) < 1 + len_bytes:
        raise ValueError("corrupted input – length field incomplete")

    # read the length value, which is left-aligned (MSB-aligned) in `len_bits`
    len_int = int.from_bytes(raw[1:1 + len_bytes], "big")
    n_shift = 8 * len_bytes - len_bits
    n = (len_int >> n_shift) & ((1 << len_bits) - 1)
    if n == 0:
        return np.empty(0, dtype=_dtype_for_bits(bits))
    # print(f"len_int: {len_int}")

    # --------------------------------------------------------------------
    # 2.  Vectorised extraction of `n` packed values
    # --------------------------------------------------------------------
    payload = np.frombuffer(raw, dtype=np.uint8)  # no copy
    # pad with four zero bytes so we can safely read past the end
    payload = np.concatenate([payload, np.zeros(4, dtype=np.uint8)])

    start_bit = hdr_bits                        # first payload bit index
    idx       = start_bit + np.arange(n, dtype=np.uint64) * bits  # bit pos
    byte_idx  = (idx >> 3).astype(np.int64)     # starting byte for each value
    bit_off   = (idx & 7).astype(np.uint8)      # bit offset inside that byte

    # gather the 5 bytes that are guaranteed to contain the whole value
    gather = payload[byte_idx[:, None] + np.arange(5)]
    gather = gather.astype(np.uint64)

    # fold the 5 bytes into one 40-bit chunk (MSB first)
    shifts = np.array([32, 24, 16, 8, 0], dtype=np.uint64)
    chunks = (gather << shifts).sum(axis=1, dtype=np.uint64)

    # right-shift to drop leading padding bits, then mask
    drop   = 40 - bits - bit_off            # individual shift per element
    values = (chunks >> drop) & ((1 << bits) - 1)

    return values.astype(_dtype_for_bits(bits), copy=False)

# -----------------------------------------------------------------------------
# Tiny demo
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    original = np.array(np.random.randint(0, 17, 2**14), dtype=np.uint64)
    encoded = ndarray_to_base64(original)
    roundtrip = base64_to_ndarray(encoded)

    print("Original :", original)
    print("Encoded  :", encoded)
    print("Encoded len  :", len(encoded))
    print("Decoded  :", roundtrip, roundtrip.dtype)