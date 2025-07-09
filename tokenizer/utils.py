import numpy as np
import numpy.typing as npt
from pathlib import Path
import os

def register_name_range(id: int, basename: str) -> str:
    """
    Creates tokens for blocks.
    Block number < 16: Block_0 - Block_F
    Block number > 16: Block_Lit_Start Block_Lit_1 Block_Lit_0 Block_Lit_End
    """

    """
    Creates tokens for block indexes.
    Block number < 255: Block_0 -  Block_F
    Block number > 255: Block_Lit_Start Block_{HEX VALUE} Block_{HEX VALUE} Block_Lit_End"""
    
    id_str = hex(id)[2:].upper()
    chunks = [id_str[i: i+2] for i in range(0, len(id_str), 2)]
    name = f"{basename}_Lit_Start"
    for element in chunks:
        name += f" {basename}_{element}"
    name += f" {basename}_Lit_End"
    return name

def run_length_and_last_type(type_ids: npt.NDArray[np.int_], start_set: npt.NDArray[np.int_],
                             end_set: npt.NDArray[np.int_]) -> (npt.NDArray[np.int_], npt.NDArray[np.int_]):
    # Step 1: Create masks for start and end values
    start_mask = np.isin(type_ids, start_set)
    end_mask = np.isin(type_ids, end_set)

    # Step 2: Get the indices where starts and ends occur
    arange = np.arange(len(type_ids), dtype=np.uint32)
    start_idx = arange[start_mask].ravel()
    end_idx = arange[end_mask].ravel()  # probably better contiguous
    assert len(start_idx) == len(end_idx), "invalid data: some literals do not open or close"
    if len(start_idx) == 0:
        return np.ones_like(type_ids, dtype=np.uint8), type_ids

    # Step 2: using cumsum we can model the problem as particles that annihilate with their antiparticles
    particles = start_mask.view(np.int8) - end_mask.view(np.int8)

    # Step 3: Create segment mask where we identify valid regions
    # this mask always drops to 0 one early but actually that is super useful
    # this must be int8 otherwise we cannot view it as bool later
    segment_mask = np.cumsum(particles, dtype=np.int8)
    assert np.all(np.abs(segment_mask) <= 1), "invalid data: nested literal segments"

    # Step 4: Find segment lengths
    long_segment_length = (end_idx - start_idx + 1).astype(np.uint8)
    anti_segment_mask = ~ segment_mask.view(dtype=np.bool_)
    new_segment_idx = anti_segment_mask.cumsum(dtype=np.uint32)[start_idx]

    # Step 5: Prepare result array to hold run lengths
    result = np.ones(len(type_ids) - long_segment_length.sum(dtype=np.uint32) + len(long_segment_length),
                     dtype=np.uint8)

    # Step 6: Assign run lengths based on the identified segments
    result[new_segment_idx] = long_segment_length

    return result, type_ids[anti_segment_mask]


def CA_BArle_to_CBrle(c_to_a_rle: npt.NDArray[np.int_], b_to_a_rle: npt.NDArray[np.int_]) -> npt.NDArray[np.int_]:
    # we need indecies to be able to us searchsorted - require strictly increasing
    c_to_a_idx = c_to_a_rle.cumsum()
    b_to_a_idx= b_to_a_rle.cumsum()

    # right side matches cumsum the excluded ending index
    x = np.searchsorted(c_to_a_idx, b_to_a_idx, side='right')
    # these are indecies so we need to convert back to runlengths encoding
    b_to_a_idx[1:] = x[1:] - x[:-1]
    return b_to_a_rle



def filter_queue_file_by_existing_output(queue_file: str, out_dir: str = "out") -> None:
    """
    Removes lines from the queue file if a corresponding output CSV already exists in the out/ directory.
    """
    filtered_lines = []

    with open(queue_file, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    print(len(lines))

    for binary_path in lines:
        binary_name = os.path.basename(binary_path)
        try:
            relative_path = Path(binary_path).relative_to("src")
        except ValueError:
            print(f"[!] Skipping non-src path: {binary_path}")
            continue

        output_csv = Path(out_dir) / relative_path.parent / f"{binary_name}_functions.csv"

        if not output_csv.exists():
            filtered_lines.append(binary_path)
        else:
            print(f"[~] Skipping {binary_path} (output exists at {output_csv})")

    with open(queue_file, "w") as f:
        for line in filtered_lines:
            f.write(f"{line}\n")

    print(f"[+] Filtered queue file {queue_file}: {len(filtered_lines)} items remaining.")

def pop_first_line(queue_file: str) -> str | None:
    with open(queue_file, "r") as f:
        lines = f.readlines()

    if not lines:
        return None

    first_line = lines[0].strip()

    with open(queue_file, "w") as f:
        f.writelines(lines[1:])

    return first_line