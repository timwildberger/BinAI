import angr
import csv
import os
import sys
import re
import ailment
import time
from pathlib import Path
from multiprocessing import Pool
from typing import Tuple
from binary_filter import BinaryFilter

RE_MULTI_WS = re.compile(r"\s+")
RE_THREE_BEFORE_PIPE = re.compile(r".{3}\|")

def sanitize(text):
    return text.replace("\n", " ").replace("\r", "").replace('"', "'")

def ensure_single_space(text: str) -> str:
    return RE_MULTI_WS.sub(" ", text)

def remove_newline(text):
    return text.replace("\n", " ").replace("\t", " ").replace(" ------ ", " ").replace("IRSB { ", " ").strip()

def remove_three_before_pipe(s):
    return RE_THREE_BEFORE_PIPE.sub("|", s)

def split_at_first_instruction(text):
    marker = "00 |"
    idx = text.find(marker)
    if idx == -1:
        return text, ""
    return text[:idx].strip(), text[idx:].strip()

ail_manager_cache = {}

def get_ail_manager(arch):
    if arch not in ail_manager_cache:
        ail_manager_cache[arch] = ailment.Manager(arch=arch)
    return ail_manager_cache[arch]

def lowlevel_disas(cfg):
    function_bbs = {}
    for func_addr, func in cfg.functions.items():
        if func.name.startswith('sub_') or func.name in ['UnresolvableCallTarget', 'UnresolvableJumpTarget']:
            continue
        temp_bbs = {}
        for block in func.blocks:
            block_addr = block.addr
            disassembly = block.capstone.insns
            disassembly_list = [(insn.mnemonic, insn.op_str) for insn in disassembly]
            temp_bbs[hex(block_addr)] = disassembly_list
        function_bbs[func_addr] = temp_bbs
    return function_bbs

def highlevel_disas(func) -> str:
    disasm_lines = [str(block.disassembly) for block in func.blocks]
    disasm_str = (" ".join(disasm_lines))
    #disasm_str = sanitize(" ".join(disasm_lines))
    return disasm_str
    #return ensure_single_space(disasm_str)

def process_vex_block(addr, block) -> str:
    try:
        if block.vex is None:
            raise ValueError("No VEX IR available")
        irsb_str = str(block.vex)
        #irsb = remove_newline(irsb_str)
        #irsb = ensure_single_space(irsb)
        #temp, body = split_at_first_instruction(irsb)
        #body2 = remove_three_before_pipe(body)
        return irsb_str
    except Exception as e:
        return f"[!] VEX error @ {hex(addr)}: {type(e).__name__}: {e}"

def process_ail_block(addr, block, man) -> list[str]:
    try:
        irsb = block.vex
        if irsb is None or irsb.statements is None:
            raise ValueError("Empty or invalid IRSB")

        ail_block = ailment.IRSBConverter().convert(irsb=irsb, manager=man)
        if ail_block is None or ail_block.statements is None:
            raise ValueError("AIL block conversion failed or empty")

        result = [f"Block 0x{addr:x}:"]
        result += [f"{stmt} " for stmt in ail_block.statements]
        return result
    except Exception as e:
        return [f"[!] AIL error @ 0x{addr:x}: {type(e).__name__}: {e}"]

def vex_repr(func, project) -> str:
    vex_lines = []
    for addr in func.block_addrs:
        try:
            block = project.factory.block(addr, opt_level=0)
            vex_lines.append(process_vex_block(addr, block))
        except Exception as e:
            vex_lines.append(f"[!] VEX error @ {hex(addr)}: {type(e).__name__}: {e}")
    #return sanitize(" ".join(vex_lines))
    return (" ".join(vex_lines))

def ail_repr(func, project, man) -> str:
    ail_lines = []
    for addr in func.block_addrs:
        try:
            block = project.factory.block(addr, opt_level=0)
            ail_lines.extend(process_ail_block(addr, block, man))
        except Exception as e:
            ail_lines.append(f"[!] AIL error @ 0x{addr:x}: {type(e).__name__}: {e}")
    return (" ".join(ail_lines))
    #return ensure_single_space(sanitize(" ".join(ail_lines)))

def decompilation(func, project, cfg) -> str:
    try:
        dec = project.analyses.Decompiler(func, cfg=cfg)
        if dec is None or dec.codegen is None:
            return "Decompilation failed or empty output"
        decomp_str = dec.codegen.text
        # decomp_str = sanitize(dec.codegen.text)
        return re.sub(r"\s+", " ", decomp_str)
    except Exception as e:
        return f"Decompilation failed: {e}"

def get_section_name(project, addr):
    for section in project.loader.main_object.sections:
        if section.contains_addr(addr):
            return section.name
    return "UNKNOWN"

def init_worker(binary_path):
    global project, man, cfg
    project = angr.Project(binary_path, auto_load_libs=False)
    man = get_ail_manager(project.arch)
    cfg = project.analyses.CFGFast(normalize=True)

def worker_func(func_addr) -> Tuple[dict, dict]:
    func = project.kb.functions[func_addr]

    func_name = func.name
    section_name = get_section_name(project, func_addr)

    t0 = time.perf_counter()
    high_dis_str = highlevel_disas(func)
    high_dis_time = time.perf_counter() - t0

    t2 = time.perf_counter()
    vex_str = vex_repr(func, project)
    vex_time = time.perf_counter() - t2

    t4 = time.perf_counter()
    ail_str = ail_repr(func, project, man)
    ail_time = time.perf_counter() - t4

    t6 = time.perf_counter()
    decomp_str = decompilation(func, project, cfg)
    decomp_time = time.perf_counter() - t6

    times = {
        "HDISAS": high_dis_time,
        "VEX": vex_time,
        "AIL": ail_time,
        "DECOMP": decomp_time
    }

    return ({
        "func_addr": func_addr,
        "func_name": func_name,
        "section_name": section_name,
        "highlevel": high_dis_str,
        "ail": ail_str,
        "vex": vex_str,
        "decomp": decomp_str
    }, times)


def extract_function_data_parallel(binary_path, num_workers=4):
    project_main = angr.Project(binary_path, auto_load_libs=False)
    print("[*] Generating CFG for lowlevel disassembly...")
    cfg_main = project_main.analyses.CFGFast(normalize=True)

    print("[*] Running low-level disassembly (single-threaded)...")
    t0 = time.perf_counter()
    lowlevel_results = lowlevel_disas(cfg_main)
    l_disas_time = round(time.perf_counter() - t0, 2)

    # Original binary path (e.g., src/clamav/filename)
    binary_name = os.path.basename(binary_path)

    # Get relative path after 'src/'
    relative_path = Path(binary_path).relative_to("src")

    # Replace 'src' with 'out'
    output_path = Path("out") / relative_path.parent
    output_path.mkdir(parents=True, exist_ok=True)

    # Final CSV file path
    csv_path = output_path / f"{binary_name}_functions.csv"

    func_addrs = [fa for fa, _ in project_main.kb.functions.items()]

    total_times = {
        "LDISAS": l_disas_time,
        "HDISAS": 0.0,
        "VEX": 0.0,
        "AIL": 0.0,
        "DECOMP": 0.0
    }

    print(f"[*] Starting multiprocessing with {num_workers} workers...")
    with Pool(processes=num_workers, initializer=init_worker, initargs=(binary_path,)) as pool:
        results_with_times = pool.map(worker_func, func_addrs)
        results = [r for r, _ in results_with_times]
        for t in [t for _, t in results_with_times]:
            for key in total_times:
                total_times[key] += t.get(key, 0.0)

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["FunctionName", "Section", "HighDisasm", "LowDisasm", "AIL", "VEX", "Decompilation"])

        for res in results:
            func_addr = res["func_addr"]
            low_dis_str = ""
            for block_addr, insns in lowlevel_results.get(func_addr, {}).items():
                insn_str = "; ".join(f"{m} {o}" for m, o in insns)
                low_dis_str += f"Block {block_addr}: {insn_str} | "

            writer.writerow([
                res["func_name"],
                res["section_name"],
                f'<HDIS> {res["highlevel"]} </HDIS>',
                f'<LDIS> {low_dis_str} </LDIS>',
                f'<AIL> {res["ail"]} </AIL>',
                f'<VEX> {res["vex"]} </VEX>',
                f'<DECOMP> {res["decomp"]} </DECOMP>',
            ])

    return total_times, csv_path



def pop_first_line(queue_file: str) -> str | None:
    with open(queue_file, "r") as f:
        lines = f.readlines()

    if not lines:
        return None

    first_line = lines[0].strip()

    with open(queue_file, "w") as f:
        f.writelines(lines[1:])

    return first_line


def main():

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <queue_file>")
        sys.exit(1)

    queue_file = sys.argv[1]
    # your processing here
    print(f"Using queue: {queue_file}")
    while True:
        binary_path = pop_first_line(queue_file)

        if binary_path is None:
            print("Queue is empty. Exiting.")
            break

        if binary_path is None:
            print("Queue is empty. Exiting.")
            break

        print(f"\n[*] Processing binary: {binary_path}")
        start_time = time.perf_counter()
        total_times, csv_path = extract_function_data_parallel(binary_path, num_workers=8)
        end_time = time.perf_counter()

        print("\n=== Total Time per Representation (sum of all functions) ===")
        for key, val in total_times.items():
            if key == "LDISAS":
                print(f"{key:8}: {val:.2f} seconds (single-threaded)")
            elif key == "DECOMP":
                print(f"{key:8}: -- (timing not summed due to multiprocessing)")
            else:
                print(f"{key:8}: {val:.2f} seconds (summed over all functions)")

        print(f"\nTotal wall-clock analysis time: {end_time - start_time:.2f} seconds (parallel elapsed time)")
        print(f"[+] Done. Data saved to {csv_path}")
        break

if __name__ == "__main__":
    main()

# TODO separater aufruf des queueing und filters um Files zu erstellen

# TODO pfad zur queue als parameter für den Decompiler

# TODO Preprocessing der strings für die csv rausnehmen und nur so ändern, dass die csv nicht zerlegt wird