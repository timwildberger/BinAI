"""
This code is taken from the pandas library, specifically from the `pandas.util.hashing` module.
It is modified to only work with numpy
https://github.com/pandas-dev/pandas/blob/main/pandas/core/util/hashing.py
apparently under BSD 3-Clause License
"""

from __future__ import annotations


import numpy as np

def _w2_iter(iterable):
    iterable = iter(iterable)
    last = next(iterable)
    for current in iterable:
        yield last, current
        last = current


primes = np.array([0xBF58476D1CE4E5B9, 0x94D049BB133111EB])
primes_idx_mask = len(primes) - 1
def hash_continuous_array(vals: np.ndarray) -> np.uint64:
    """
    Hash function that:
    1. Asserts continuous array
    2. Views as u8 then ravel
    3. Takes u64 aligned view and unaligned ends
    4. Copies first 1024 bits of aligned (or next smaller power of 2)
    5. Views copy as u64
    6. If 1024 bits, loops through index and collects hash
    7. Applies remaining non-1024 bit aligned data
    8. Applies unaligned end
    9. Folds the array progressively until one u64 hash
    """
    # Step 1: Assert continuous
    assert vals.flags.c_contiguous, "Array must be C-contiguous"

    # Step 2: View as u8 then ravel
    u8_view = vals.view(np.uint8).ravel()

    # Step 3: Take u64 aligned view and unaligned ends
    total_bytes = len(u8_view)
    aligned_bytes = (total_bytes >> 3) << 3
    unaligned = np.zeros(1, dtype=np.uint64)
    unaligned_u8 = unaligned.view(np.uint8)
    unaligned_u8[:total_bytes-aligned_bytes] = u8_view[aligned_bytes:]

    # Early return if no aligned bytes
    if aligned_bytes == 0:
        return unaligned

    aligned_view = u8_view[:aligned_bytes].view(np.uint64)

    # Step 4: Copy first 1024 bits of aligned (or next smaller power of 2)
    # 1024 bits = 128 bytes = 16 u64 values
    max_u64_count = 16  # 1024 bits / 64 bits per u64
    copy_size = min(max_u64_count, 1 << (len(aligned_view).bit_length() - 1))
    log2_u64_per = copy_size.bit_length() - 1
    mask_u64_per = (1 << log2_u64_per) - 1
    rowwise_hash = aligned_view[:copy_size].copy()
    # rowwise_hash ^= rowwise_hash << np.arange(max_u64_count, dtype=np.uint8)

    i = 0
    end = max_u64_count
    if copy_size == max_u64_count:
        for i, (start, end) in enumerate(_w2_iter(range(max_u64_count, len(aligned_view)+1, max_u64_count))):
            p = i & primes_idx_mask
            rowwise_hash *= primes[p]
            rowwise_hash ^= rowwise_hash >> 23
            rowwise_hash ^= aligned_view[start:end]

    rowwise_hash *= primes[(i+1) & primes_idx_mask]
    rowwise_hash[:len(aligned_view)-end] ^= aligned_view[end:]

    # Step 5: Fold the array progressively until one u64 hash
    for i in range(log2_u64_per-1, 0, -1):
        mid = 1 << i
        rowwise_hash[:mid] ^= rowwise_hash[mid:]
        rowwise_hash = rowwise_hash[:mid]

    # Apply unaligned at the end
    return rowwise_hash[0] ^ unaligned[0]
