import numpy as np
import numpy.typing as npt

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




def CA_BArle_to_CBrle(c: npt.NDArray[np.int_], b: npt.NDArray[np.int_]) -> npt.NDArray[np.int_]:
    # we need indecies to be able to us searchsorted - require strictly increasing
    c = c.cumsum()
    b = b.cumsum()

    # right side matches cumsum the excluded ending index
    x = np.searchsorted(c, b, side='right')
    # these are indecies so we need to convert back to runlengths encoding
    b[1:] = x[1:] - x[:-1]
    return b

from pathlib import Path
import os


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