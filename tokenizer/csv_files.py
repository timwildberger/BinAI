import csv
import re
from pathlib import Path

import numpy as np

from tokenizer.compact_base64_utils import base64_to_ndarray, base64_to_ndarray_vec
from tokenizer.utils import register_name_range


def extract_ldis_blocks_from_file(file_path):
    """
    Reads a structured CSV-like file and extracts disassembly blocks from <LDIS> tags.
    Returns a dict: function_name -> list of disassembled blocks.
    """
    file_path = Path(file_path)
    result = {}

    with file_path.open(encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 4:
                continue

            funcname = row[0]
            ldis_field = row[3]

            # Extract content between <LDIS> and </LDIS>
            match = re.search(r"<LDIS>(.*?)</LDIS>", ldis_field, flags=re.DOTALL)
            if match:
                ldis_text = match.group(1).strip()
                # Optional: split blocks if separated by "|"
                blocks = [b.strip() for b in ldis_text.split("|")]
                result[funcname] = blocks
    return result


def parse_and_save_data_sections(
        proj, sections_to_parse: list[str] = [".rodata"], output_txt="parsed_constants.txt"
) -> dict[str, list[str]]:
    """
    Parses the .rodata (read-only data) section to retrieve a dict with all constants.

    Args:
        proj: angr Project
        sections_to_parse (list[str]): Contains per default only '.rodata'
        output_txt (str): Name of the file for persistence

    Returns:
        dict with all constants of structure: start_addr: [end_addr, section_name, value]
    """
    all_entries = []
    addr_dict: dict[str, list[str]] = {}

    def parse_rodata(data, base_addr):
        entries = []
        for match in re.finditer(b"[\x20-\x7e]{4,}\x00", data):
            s = match.group().rstrip(b"\x00").decode("utf-8", errors="ignore")
            start = base_addr + match.start()
            entries.append(
                {
                    "section": ".rodata",
                    "start": hex(start),
                    "end": hex(start + len(s) + 1),
                    "value": f'"{s}"',
                }
            )
        return entries

    # Only process .rodata or other truly constant sections
    for sec in proj.loader.main_object.sections:
        if sec.name not in sections_to_parse:
            continue
        if sec.name == ".rodata" and sec.is_readable and sec.memsize > 0:
            data = proj.loader.memory.load(sec.vaddr, sec.memsize)
            entries = parse_rodata(data, sec.vaddr)
            all_entries.extend(entries)
            for e in entries:
                addr_dict[e["start"]] = [e["end"], e["section"], e["value"]]

    # Output only exact-address constants
    with open(output_txt, "w") as f:
        for e in all_entries:
            f.write(f'{e["start"]} - {e["end"]}: {e["section"]}: {e["value"]}\n')

    print(
        f"Parsed {len(all_entries)} .rodata constants with exact addresses into {output_txt}"
    )
    return addr_dict


def parse_init_sections(
        proj, output_txt="parsed_init_sections.txt", sections_to_parse=None
):
    """
    Parse ELF .init/.fini/.init_array/.fini_array sections and write to file.

    Args:
        proj (angr.Project): Loaded angr project.
        output_txt (str): Output file to write parsed content.
        sections_to_parse (list[str], optional): Section names to parse. Defaults to init/fini types.

    Returns:
        list[dict]: list of parsed section entries.
    """
    if sections_to_parse is None:
        sections_to_parse = [".init", ".fini", ".init_array", ".fini_array"]

    entries = []

    with open(output_txt, "w") as f:
        f.write("# Parsed init/fini related sections\n")

        for section in proj.loader.main_object.sections:
            if section.name not in sections_to_parse:
                continue

            try:
                data = proj.loader.memory.load(section.vaddr, section.memsize)
            except Exception as e:
                print(f"Warning: could not read section {section.name}: {e}")
                continue

            if section.name.endswith("_array"):
                word_size = proj.arch.bytes
                for i in range(0, len(data), word_size):
                    chunk = data[i: i + word_size]
                    if len(chunk) != word_size:
                        continue
                    val = int.from_bytes(chunk, byteorder="little")
                    entry = {
                        "section": section.name,
                        "start": hex(section.vaddr + i),
                        "end": hex(section.vaddr + i + word_size),
                        "value": hex(val),
                        "type": "pointer",
                    }
                    entries.append(entry)
                    f.write(
                        f"{entry['section']}, {entry['start']} - {entry['end']}: {entry['value']} (ptr)\n"
                    )
            else:
                hex_preview = data[:32].hex()
                entry = {
                    "section": section.name,
                    "start": hex(section.vaddr),
                    "end": hex(section.vaddr + section.memsize),
                    "value": f"hex({hex_preview}...)",
                    "type": "code",
                }
                entries.append(entry)
                f.write(
                    f"{entry['section']}, {entry['start']} - {entry['end']}: {entry['value']} (code)\n"
                )

    print(f"Parsed {len(entries)} entries from init-related sections into {output_txt}")
    return entries


def reverse_tokenization(
        tokenized_instructions: np.ndarray,
        block_run_lengths: list[int],
        insn_run_lengths: list[int],
        vocab: dict[int, str]
) -> list[dict[str, list[str]]]:
    instructions = []
    token_index = 0
    # Step 1: Convert tokens into instructions
    for insn_len in insn_run_lengths:
        insn_tokens = []

        for _ in range(insn_len):
            token_id = int(tokenized_instructions[token_index])
            """if vocab[token_id] == "VALUED_CONST_34":
                print(f"token_id={token_id}, token={vocab[token_id]}")
                print(f"Tokenized instructions: {tokenized_instructions}")
                return None"""
            insn_tokens.append(vocab[token_id])
            token_index += 1
        instructions.append(insn_tokens)

    # print(instructions)

    # Step 2: Group instructions into blocks
    block_insns = []

    insn_index = 0
    block_index = 0
    j = 0  # index over all instructions
    for block_len in block_run_lengths:
        i = 0  # index that is being reset for each block
        block_instrs = []
        # print(block_len)
        while i < block_len:
            block_instrs.append(' '.join(instructions[j]))
            i += len(instructions[j])
            # print(f"\t{i}")
            j += 1
        if block_index < 16:
            block_insns.append({
                f'Block_{hex(block_index)[2:].upper()}': block_instrs
            })
        else:
            block_insns.append({
                f'{register_name_range(block_index, basename="Block")}': block_instrs
            })
        block_index += 1

    # print(block_insns)
    return block_insns


def vocab_from_output(output_path: str) -> list[str]:
    with open(output_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        csv_iter = iter(reader)
        vocab: list[str] = []
        for func_name, token in enumerate(next(csv_iter)[6][1:-1].split(",")):
            vocab.append(token)
    return vocab


def token_to_insn(input_path: str, output_path: str):
    with open(input_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        token_list: list[tuple[str, str]] = []
        vocab: dict[int, str] = {}
        csv_iter = iter(reader)
        for func_name, token in enumerate(next(csv_iter)[6][1:-1].split(",")):
            vocab[func_name] = token

        for row in reader:
            function_name = row[0]
            print(f"Function name: {function_name}")

            tokens = base64_to_ndarray_vec(row[2])
            block_runlength = base64_to_ndarray_vec(row[3])
            insn_runlength = base64_to_ndarray_vec(row[4])
            string_stream = reverse_tokenization(tokens, block_runlength, insn_runlength, vocab)
            token_list.append((function_name, string_stream))

    with open(output_path, mode="w", newline='', encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        for k, v in token_list:
            writer.writerow([k, v])


def datastructures_to_insn(vocab: dict[int, str],
                           token_dict: dict[str, str],
                           block_runlength_dict: dict[str, str],
                           insn_runlength_dict: dict[str, str],
                           duplicate_map: dict[str, str]):
    reconstructed: dict[str, str] = {}
    vocab = {v: k for k, v in vocab.items()}

    for index in token_dict:
        try:
            # Resolve duplicates (use original name if it's a duplicate)
            original_index = duplicate_map.get(index, index)

            tokens = base64_to_ndarray(token_dict[index])
            block_runlength = base64_to_ndarray(block_runlength_dict[index])
            insn_runlength = base64_to_ndarray(insn_runlength_dict[index])

            string_stream = reverse_tokenization(tokens, block_runlength, insn_runlength, vocab)
            reconstructed[original_index] = string_stream

        except Exception as e:
            print(f"❌ Failed to process index {index}: {e}")

    # Write the result to a CSV
    with open("reconstructed_disassembly_test.csv", mode="w", newline='', encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        for k, v in reconstructed.items():
            writer.writerow([k, v])


def compare_csv_files(file1: str, file2: str):
    # Increase CSV field size limit
    csv.field_size_limit(10_000_000)

    with open(file1, newline='', encoding='utf-8') as f1, open(file2, newline='', encoding='utf-8') as f2:
        reader1 = csv.reader(f1)
        reader2 = csv.reader(f2)

        line_num = 1
        for row1, row2 in zip(reader1, reader2):
            if row1 != row2:
                print(f"Mismatch at line {line_num}:")
                print(f"  {file1}: {row1}")
                print(f"  {file2}: {row2}")
                raise ValueError
            line_num += 1

        for row in reader1:
            print(f"Extra line in {file1} at line {line_num}: {row}")
            line_num += 1

        for row in reader2:
            print(f"Extra line in {file2} at line {line_num}: {row}")
            line_num += 1


def csv_to_dict(filepath):
    result = {}
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) != 2:
                continue  # skip malformed lines
            key, value = row[0].strip(), row[1].strip()
            try:
                result[key] = int(value)
            except ValueError:
                result[key] = value  # fallback if not int
    return result
