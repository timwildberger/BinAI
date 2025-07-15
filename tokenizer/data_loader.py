import csv
import io

import numpy as np
import os

def main():
    data = np.memmap(r"out\zlib\x86-gcc-9-Os_minigzipsh_output.csv", dtype=np.uint8, mode="r")
    chunk_size = 1 << 14  # 16,384

    num_chunks = (np.size(data) + chunk_size - 1) // chunk_size  # Ceiling division

    last_line_chunk = None
    for i in range(num_chunks):
        start = min(-(i + 1) << 14, -np.size(data))
        end = -(i << 14) if (i << 14) != 0 else None
        chunk = data[start:end]

        # Create mask for ASCII 10 ('\n') or 13 ('\r')
        mask = (chunk == 10) | (chunk == 13)

        print(f"Chunk {i}: data[{start}:{end}] → shape {chunk.shape}, matches: {np.sum(mask)} linebreaks")

        if np.any(mask):
            last_local_index = np.where(mask)[0][-1]  # Position in the chunk
            last_global_index = (np.size(data) + start) + last_local_index  # Global position in the file
            last_line_chunk = chunk[last_local_index:]
            break;
            print(f"  Last linebreak: local index {last_local_index}, global index {last_global_index}")
        else:
            print(f"  No linebreaks found in this chunk.")

    csv_data = io.BytesIO(last_line_chunk.tobytes())
    reader = csv.reader(io.TextIOWrapper(csv_data, encoding='ascii'))
    for row in reader:
        print(row)

if __name__ == "__main__":
    main()
