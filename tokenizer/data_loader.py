import csv
import io
from pathlib import Path
from typing import Literal

import numpy as np
import os

from tokenizer.architecture import PlatformInstructionTypes
from tokenizer.compact_base64_utils import base64_to_ndarray, ndarray_to_base64
from tokenizer.token_manager import VocabularyManager
from tokenizer.tokens import TokenType

Platform = Literal["x86", "x64", "arm", "arm64", "unified"]


def load_vocab_manager_csv_row_bytes(csv_row: bytes, platform: Platform) -> VocabularyManager:
    csv_data = io.BytesIO(csv_row)
    reader = csv.reader(io.TextIOWrapper(csv_data, encoding='ascii'), quotechar='"')
    row = next(reader)
    assert len(row) == 10 or (platform == "unified" and len(row) == 13), f"Expected 10 or 13 columns, got {len(row)}"
    assert row[0] == "vocabulary"
    assert row[2].startswith("_id_to_token_type")
    assert row[4].startswith("_platform_instruction_type_cache")
    assert row[6] == "_lit_start_cache"
    assert row[8] == "_lit_end_cache"
    if platform == "unified":
        assert row[9].startswith("platforms")

    vocabulary = row[1].strip('"').split(",")
    id_to_token_type_offset = int(row[2].partition("norm:")[2])
    platform_instruction_type_cache_offset = int(row[4].partition("norm:")[2])
    id_to_token_type = base64_to_ndarray(row[3]).astype(np.int8)+id_to_token_type_offset
    platform_instruction_type_cache = base64_to_ndarray(row[5]).astype(np.int8)+platform_instruction_type_cache_offset
    lit_start_cache =  base64_to_ndarray(row[7]).astype(np.int_)
    lit_end_cache =  base64_to_ndarray(row[9]).astype(np.int_)
    platform_offset = int(row[10].partition("norm:")[2]) if platform == "unified" else None
    platform_list = row[11].strip('"').split(",") if platform == "unified" else None
    token_to_platform = base64_to_ndarray(row[12]).astype(np.int8) + platform_offset if platform == "unified" else None

    platform = platform if platform != "unified" else None

    return VocabularyManager.from_vocab(platform=platform,
                                        vocab_list=vocabulary,
                                        id_to_token_type=id_to_token_type,
                                        platform_instruction_type_cache=platform_instruction_type_cache,
                                        lit_start_cache=lit_start_cache,
                                        lit_end_cache=lit_end_cache,
                                        platform_list=platform_list,
                                        token_to_platform=token_to_platform)

def load_vocab_manager(csv_path: Path, platform = None) -> VocabularyManager:
    if platform is None:
        platform_options = Platform.__args__
        file_name = csv_path.name
        for option in platform_options:
            if file_name.startswith(option):
                platform = option
                break

    assert platform is not None, f"Could not determine platform from file name: {csv_path.name}"


    # data = np.memmap(r"out\zlib\x86-gcc-9-Os_minigzipsh_output.csv", dtype=np.uint8, mode="r")
    data = np.memmap(csv_path, dtype=np.uint8, mode="r")
    search_area = data[:-64]
    chunk_size = 1 << 14  # 16,384

    num_chunks = (np.size(search_area) + chunk_size - 1) // chunk_size  # Ceiling division

    last_line_chunk = None
    for i in range(num_chunks):
        start = max(-(i + 1) << 14, -np.size(search_area))
        end = -(i << 14) if (i << 14) != 0 else None
        chunk = search_area[start:end]

        # Create mask for ASCII 10 ('\n') or 13 ('\r')
        mask = (chunk == 10) | (chunk == 13)
        # print(f"Chunk {i}: search_area[{start}:{end}] → shape {chunk.shape}, matches: {np.sum(mask)} linebreaks")

        if np.any(mask):
            last_local_index = np.where(mask)[0][-1]  # Position in the chunk
            last_global_index = (np.size(search_area) + start) + last_local_index + 1 # Global position in the file
            last_line_chunk = data[last_global_index:]
            break;
        #     print(f"  Last linebreak: local index {last_local_index}, global index {last_global_index}")
        # else:
        #     print(f"  No linebreaks found in this chunk.")

    return load_vocab_manager_csv_row_bytes(last_line_chunk.tobytes(), platform)

def save_vocabulary(vocab_manager, csv_writer):
    token_count = len(vocab_manager.id_to_token)
    row = [
        "vocabulary",
        ",".join(vocab_manager.id_to_token),
        f"_id_to_token_type norm:{0 + TokenType.UNRESOLVED}",
        # need to normalize as ndarray_to_base64 only supports >= 0
        ndarray_to_base64(vocab_manager._id_to_token_type[:token_count] - TokenType.UNRESOLVED),
        f"_platform_instruction_type_cache norm:{0 + PlatformInstructionTypes.UNRESOLVED}",
        # need to normalize as ndarray_to_base64 only supports >= 0
        ndarray_to_base64(vocab_manager._platform_instruction_type_cache[
                          :token_count] - PlatformInstructionTypes.UNRESOLVED),
        "_lit_start_cache",
        ndarray_to_base64(vocab_manager._lit_start_cache[:vocab_manager._lit_start_count]),
        "_lit_end_cache",
        ndarray_to_base64(vocab_manager._lit_end_cache[:vocab_manager._lit_end_count]),
    ]


    if vocab_manager.platform is None:
        platform_norm = -1
        extra = [
            f"platforms norm:{platform_norm}",
            ",".join(vocab_manager.platform_list),
            ndarray_to_base64(vocab_manager.token_to_platform[:token_count] - platform_norm),
        ]
        row += extra

    csv_writer.writerow(row)


def unify_vocab(csv_files: list[Path], output_path: Path) -> None:
    unified_vm = VocabularyManager(platform=None)

    for csv_file in csv_files:
        print(f"Loading vocabulary from {csv_file}")
        current_vocab_manager = load_vocab_manager(csv_file)
        mappings = np.full_like(current_vocab_manager.id_to_token_type, -1, dtype=np.int32)

        for tokens in current_vocab_manager.iter_representative_tokens():
            original = tokens.get_token_ids()
            mapped = tokens.register_on_vocab_manager(unified_vm).get_token_ids()
            assert len(original) == len(mapped)
            for original_id, mapped_id in zip(original, mapped):
                mappings[original_id] = mapped_id

        assert np.all(mappings >= 0)


        mapping_file_path = csv_file.with_suffix(".mapping.b64c")
        with open(mapping_file_path, "w", newline='', encoding='ascii') as mapping_file:
            mapping_file.write(ndarray_to_base64(mappings))



    print(f"Saving unified vocabulary to {output_path}")
    with open(output_path, "w", newline='', encoding='ascii') as csvfile:
        writer = csv.writer(csvfile)
        save_vocabulary(unified_vm, writer)


if __name__ == "__main__":
    unify_vocab([Path("../out/clamav/x86-gcc-5-O3_minigzipsh_output.csv").resolve(),
                 Path("../out/clamav/x64-gcc-5-O3_minigzipsh_output.csv").resolve(),
                 Path("../out/clamav/x86-gcc-5-O3_minigzipsh_output.csv").resolve()],
                Path("../out/unified_vocab.csv").resolve())
    # vm = load_vocab_manager(Path("../out/clamav/x86-gcc-5-O3_minigzipsh_output.csv").resolve())
