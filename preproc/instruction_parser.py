import os
import re
import pickle
from collections import Counter
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile
from tqdm import tqdm

# Extract symbols from the ELF file (functions, labels, etc.)
def extract_symbols(binary_path):
    symbol_map = {}
    with open(binary_path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return symbol_map
        for section in elf.iter_sections():
            if section.name == '.symtab':
                for symbol in section.iter_symbols():
                    if symbol.entry['st_value'] != 0:
                        symbol_map[symbol.entry['st_value']] = symbol.name
    return symbol_map

# Extract strings from .rodata or .data
def extract_strings(binary_path):
    string_map = {}
    with open(binary_path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if section.name in ['.rodata', '.data']:
                data = section.data()
                offset = section['sh_addr']
                strings = re.findall(b"[ -~]{4,}", data)
                for s in strings:
                    addr = data.find(s)
                    if addr >= 0:
                        string_map[offset + addr] = s.decode(errors="ignore")
    return string_map

# Normalize and tokenize instructions
def normalize_instruction(insn_str, symbol_map, string_map):
    insn_str = re.sub(r"\s+", ", ", insn_str.strip(), 1)
    parts = insn_str.split(", ")
    if not parts:
        return []

    tokens = [parts[0]]
    for operand in parts[1:]:
        symbols = re.split(r"([0-9A-Za-z_]+)", operand)
        symbols = [s for s in symbols if s.strip()]
        processed = []
        for s in symbols:
            if s.startswith("0x") and 6 < len(s) < 15:
                try:
                    addr = int(s, 16)
                    if addr in symbol_map:
                        processed.append("SYMBOL")
                    elif addr in string_map:
                        processed.append("STRING")
                    else:
                        processed.append("ADDRESS")
                except:
                    processed.append(s)
            else:
                processed.append(s)
        tokens.extend(processed)
    return tokens

# Disassemble and tokenize binary
def disassemble_and_tokenize(binary_path, symbol_map, string_map):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    with open(binary_path, "rb") as f:
        code = f.read()

    all_tokens = []
    for insn in tqdm(md.disasm(code, 0x0), desc="Disassembling"):
        tokens = normalize_instruction(insn.mnemonic + " " + insn.op_str, symbol_map, string_map)
        all_tokens.extend(tokens)

    return all_tokens

# Save vocabulary as pickle
def save_vocab(counter, vocab_path, max_size=10000, min_freq=1):
    specials = ['<pad>', '<unk>']
    words = [w for w, f in counter.most_common() if f >= min_freq][:max_size]
    vocab = specials + words
    stoi = {tok: i for i, tok in enumerate(vocab)}
    with open(vocab_path, "wb") as f:
        pickle.dump({"itos": vocab, "stoi": stoi}, f)
    print(f"✅ Saved vocab to {vocab_path}, size: {len(vocab)}")
    summarize_vocab(vocab, counter)

# Human-readable summary of the vocabulary
def summarize_vocab(vocab, counter, top_n=50):
    print("\n📌 Special Tokens:")
    for tok in vocab[:5]:
        print(f"  - {tok}")

    print(f"\n📊 Top {top_n} Most Frequent Tokens:")
    top_tokens = counter.most_common(top_n)
    for i, (tok, freq) in enumerate(top_tokens):
        print(f"{i + 1:3}. {tok:<15} — {freq} occurrences")

# Full pipeline
def build_vocab(binary_path, vocab_path="vocab.pkl", max_size=10000, min_freq=1):
    print(f"🔍 Processing binary: {binary_path}")
    symbol_map = extract_symbols(binary_path)
    string_map = extract_strings(binary_path)
    tokens = disassemble_and_tokenize(binary_path, symbol_map, string_map)

    counter = Counter(tokens)
    save_vocab(counter, vocab_path, max_size, min_freq)

# Run from CLI
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("binary_path", help="Path to ELF binary")
    parser.add_argument("-o", "--output", default="vocab.pkl", help="Output vocab pickle")
    parser.add_argument("--max_size", type=int, default=10000)
    parser.add_argument("--min_freq", type=int, default=1)
    args = parser.parse_args()

    build_vocab(args.binary_path, args.output, args.max_size, args.min_freq)
