import angr
import csv
import os
import sys
import re
import ailment
import time
import logging

# Disable overly verbose angr warnings if desired
logging.getLogger("ailment.converter_vex").setLevel(logging.ERROR)

# Precompile regex for performance
RE_MULTI_WS = re.compile(r"\s+")
RE_THREE_BEFORE_PIPE = re.compile(r".{3}\|")

def sanitize(text):
    # Simplify sanitization
    return text.replace("\n", " ").replace("\r", "").replace('"', "'")

def ensure_single_space(text: str) -> str:
    return RE_MULTI_WS.sub(" ", text)

def remove_newline(text):
    # Combine all replacements into one
    return text.replace("\n", " ").replace("\t", " ").replace(" ------ ", " ").replace("IRSB { ", " ").strip()

def remove_three_before_pipe(s):
    return RE_THREE_BEFORE_PIPE.sub("|", s)

def split_at_first_instruction(text):
    marker = "00 |"
    idx = text.find(marker)
    if idx == -1:
        return text, ""
    return text[:idx].strip(), text[idx:].strip()

def disassembly(func) -> str:
    # Join with spaces and sanitize once
    disasm_lines = [str(block.disassembly) for block in func.blocks]
    disasm_str = sanitize(" ".join(disasm_lines))
    return ensure_single_space(disasm_str)

# Create ailment manager globally (reuse)
ail_manager_cache = {}

def get_ail_manager(arch):
    if arch not in ail_manager_cache:
        ail_manager_cache[arch] = ailment.Manager(arch=arch)
    return ail_manager_cache[arch]

def AIL_VEX_repr(func, project, man) -> tuple[str, str]:
    ail_lines = []
    vex_lines = []

    blocks_cache = {}

    for addr in func.block_addrs:
        try:
            if addr not in blocks_cache:
                blocks_cache[addr] = project.factory.block(addr)
            block = blocks_cache[addr]

            # ---- VEX ----
            try:
                irsb_str = str(block.vex)
                irsb = remove_newline(irsb_str)
                irsb = ensure_single_space(irsb)
                temp, body = split_at_first_instruction(irsb)
                body2 = remove_three_before_pipe(body)
                vex_lines.append(temp + body2)
            except Exception as e:
                vex_lines.append(f"VEX error at {hex(addr)}: {e}")

            # ---- AIL ----
            try:
                irsb = block.vex
                if irsb is None or irsb.statements is None:
                    raise ValueError("Empty or invalid IRSB")

                ail_block = ailment.IRSBConverter().convert(irsb=irsb, manager=man)
                if ail_block is None or ail_block.statements is None:
                    raise ValueError("AIL block conversion failed or empty")

                ail_lines.append(f"Block 0x{addr:x}:")
                stmt_texts = [f"{stmt} " for stmt in ail_block.statements]
                ail_lines.extend(stmt_texts)
            except Exception as e:
                ail_lines.append(f"[!] AIL error at 0x{addr:x}: {type(e).__name__}: {e}")

        except Exception as outer_e:
            vex_lines.append(f"Block error at 0x{addr:x}: {outer_e}")
            ail_lines.append(f"Block error at 0x{addr:x}: {outer_e}")

    ail_str = ensure_single_space(sanitize(" ".join(ail_lines)))
    vex_str = sanitize(" ".join(vex_lines))
    return ail_str, vex_str

    

def decompilation(func, project, cfg) -> str:
    try:
        dec = project.analyses.Decompiler(func, cfg=cfg)
        if dec is None or dec.codegen is None:
            return "Decompilation failed or empty output"
        decomp_str = sanitize(dec.codegen.text)
        return RE_MULTI_WS.sub(" ", decomp_str)
    except Exception as e:
        return f"Decompilation failed: {e}"

def get_section_name(project, addr):
    for section in project.loader.main_object.sections:
        if section.contains_addr(addr):
            return section.name
    return "UNKNOWN"


def extract_function_data(binary_path):
    project = angr.Project(binary_path, auto_load_libs=False)
    man = get_ail_manager(project.arch)
    binary_name = os.path.basename(binary_path)
    base_name = os.path.splitext(binary_name)[0]
    csv_path = f"{base_name}_functions.csv"
    log_path = f"{base_name}.log"

    print(f"[*] Analyzing binary: {binary_name}")
    print("[*] Generating CFG...")
    cfg = project.analyses.CFGFast(normalize=True)

    timing_stats = []

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile, \
         open(log_path, "w", encoding="utf-8") as logfile:

        writer = csv.writer(csvfile)
        writer.writerow(["FunctionName", "Section", "FunctionData"])

        kb_funcs = list(project.kb.functions.items())  # Avoid repeated dict access

        for func_addr, func in kb_funcs:
            total_start = time.perf_counter()

            func_name = func.name
            section_name = get_section_name(project, func_addr)

            # --- Disassembly ---
            t0 = time.perf_counter()
            disasm_str = disassembly(func)
            t1 = time.perf_counter()
            disasm_time = t1 - t0

            # --- AIL + VEX ---
            t2 = time.perf_counter()
            ail_str, vex_str = AIL_VEX_repr(func, project, man)
            t3 = time.perf_counter()
            ail_vex_time = t3 - t2

            # --- Decompilation ---
            t4 = time.perf_counter()
            decomp_str = decompilation(func, project, cfg)
            t5 = time.perf_counter()
            decomp_time = t5 - t4

            function_data = f"<ASM>{disasm_str}</ASM><AIL>{ail_str}</AIL><VEX>{vex_str}</VEX><C>{decomp_str}</C>"
            writer.writerow([func_name, section_name, function_data])

            logfile.write("=" * 60 + "\n")
            logfile.write(f"Function: {func_name} @ 0x{func_addr:x}\n")

            logfile.write("[Disassembly]\n")
            for block in func.blocks:
                logfile.write(f"-- Basic Block @ 0x{block.addr:x}")
                logfile.write(str(block.disassembly))
                logfile.write("\n")

            logfile.write("[VEX IR]\n")
            for addr in func.block_addrs:
                try:
                    if addr not in project.factory.block.cache:
                        project.factory.block.cache[addr] = project.factory.block(addr)
                    block = project.factory.block.cache[addr]
                    irsb = block.vex
                    logfile.write(f"-- VEX Block @ 0x{addr:x}\n{irsb}\n")
                except Exception as e:
                    logfile.write(f"[!] VEX error @ 0x{addr:x}: {e}\n")

            logfile.write("[Decompiled AIL / Pseudo-C]\n")
            logfile.write(f"{decomp_str}\n\n")

            total_end = time.perf_counter()
            total_elapsed = total_end - total_start
            timing_stats.append((func_name, total_elapsed))

            # Output per-function timing if it took more than 1 sec
            if total_elapsed > 1.0:
                print(f"[Timing] {func_name:30} total={total_elapsed:.2f}s  disasm={disasm_time:.2f}s  "
                      f"ail+vex={ail_vex_time:.2f}s  decomp={decomp_time:.2f}s")

    print(f"[+] Done. Data saved to {csv_path}")
    timing_stats.sort(key=lambda x: x[1], reverse=True)

    print("\nTop 10 slowest functions:")
    for name, t in timing_stats[:10]:
        print(f"{name:30} took {t:.4f} sec")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <binary_path>")
        sys.exit(1)
    start_time = time.perf_counter()
    extract_function_data(sys.argv[1])
    end_time = time.perf_counter()
    print(f"Code took {end_time - start_time:.2f} seconds")

# clamav:   1,7 GB
# curl:     192 MB
# nmap:     1,24 GB
# openssl:  1,31 GB
# unrar:    90 MB
# z3:       7,25 GB
# zlib:     103 MB