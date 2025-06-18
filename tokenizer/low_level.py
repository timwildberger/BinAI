import angr
import re
import csv
from pathlib import Path
from capstone import *
from typing import Tuple
"""
Blöcke 0 bis 16:
Block0, Block1, ..., BlockF

Ab 16:
BlockLitStart
BlockLit1
BlockLit0
BlockLitEnd

e.g. Block 257
BlockLitStart
BlockLit1
BlockLit0
BlockLit1
BlockLitEnd

Konstanten:
1. ValueConstants (00 to FF representing a constant of exactly that value)
2. ValueConstantLiterals (for up to 128 Bit values)
3. OpaqueConstants (16 uniqe - they represent an opaque value basically: e.g. the representation of the string "HelloWorld")
4. OpaqueConstantLiterals (if a function needs more than 16 Opaque Literals)
"""
class LowLevelTokenizer():
    def __init__(self, repr: str):
        pass

def extract_strings(byte_data, min_length=4):
    # Find all sequences of printable ASCII characters (space to ~) of length >= min_length
    pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    return [s.decode('utf-8', errors='ignore') for s in re.findall(pattern, byte_data)]

def extract_strings_with_addresses(project, section):
    data = project.loader.memory.load(section.vaddr, section.memsize)  # Get the raw bytes
    base_addr = section.vaddr
    matches = list(re.finditer(rb'[\x20-\x7e]{4,}', data))  # Find printable ASCII strings (min 4 chars)
    
    strings_with_addresses = []
    for match in matches:
        start_offset = match.start()
        string = match.group().decode('utf-8', errors='ignore')
        vaddr = f"0x{base_addr + start_offset:x}"
        strings_with_addresses.append((vaddr, string))
    
    return strings_with_addresses



# CHATGPT TEST
"""
String constants are stored in the .rodata section



"""
import angr
import re

def extract_constants_from_section(proj, section):
    """
    Extracts constants from a section, classifying them as:
    - ValueConstant (single bytes)
    - ValueConstantLiteral (multi-byte integers <= 128 bits)
    - OpaqueConstant (printable strings or unique blobs)

    Returns a dict: address -> (type_str, value)
    """
    data = proj.loader.memory.load(section.vaddr, section.memsize)
    base = section.vaddr
    const_map = {}
    print(f"DATA: {data}")

    # 1. Extract printable ASCII strings as OpaqueConstants
    for match in re.finditer(rb'[ -~]{4,}', data):  # printable ASCII >=4 chars
        addr = base + match.start()
        s = match.group().decode('utf-8', errors='ignore')
        const_map[addr] = ('OpaqueConstant', s)

    # 2. Extract single byte ValueConstants (0x00 to 0xFF)
    for offset in range(len(data)):
        addr = base + offset
        b = data[offset]
        if addr not in const_map:
            const_map[addr] = ('ValueConstant', b)

    # 3. Extract multi-byte ValueConstantLiterals for aligned chunks (up to 16 bytes)
    # We'll do a simple heuristic: if a 4/8/16-byte int is zero-padded and not string, override
    # (This is a simplified heuristic; you may want to improve it)
    sizes = [16, 8, 4]
    for size in sizes:
        for offset in range(len(data) - size + 1):
            addr = base + offset
            chunk = data[offset:offset+size]
            # Skip if any byte in chunk overlaps existing OpaqueConstant
            if any((addr+i) in const_map and const_map[addr+i][0] == 'OpaqueConstant' for i in range(size)):
                continue
            # Interpret as int
            val = int.from_bytes(chunk, 'little')
            # Only keep if not zero and not single byte already stored
            if val != 0 and all((addr+i) not in const_map or const_map[addr+i][0] != 'ValueConstantLiteral' for i in range(size)):
                for i in range(size):
                    const_map[addr + i] = ('ValueConstantLiteral', val)
    return const_map

def build_constant_map(proj):
    obj = proj.loader.main_object
    combined_map = {}
    for section in obj.sections:
        if section.name in ['.rodata', '.data', '.data.rel.ro']:
            const_map = extract_constants_from_section(proj, section)
            combined_map.update(const_map)
    print(combined_map)
    return combined_map

def classify_operand_value(value, section_ranges, known_constant_addrs):
    for section_name, start, end in section_ranges:
        if start <= value < end:
            # Looks like an address into a memory section
            if value in known_constant_addrs:
                return ("KnownMemoryConstant", known_constant_addrs[value])
            else:
                return ("MemoryAddress", f"in {section_name} at 0x{value:x}")
    # Not in any known memory-mapped section
    if 0x00 <= value <= 0xFF:
        return ("ValueConstant", value)
    elif value.bit_length() <= 128:
        return ("ValueConstantLiteral", value)
    else:
        return ("UnknownConstant", value)

def annotate_disassembly_with_constants(proj, const_map):
    cfg = proj.analyses.CFGFast()
    for func in cfg.functions.values():
        for block in func.blocks:
            for insn in block.capstone.insns:
                tokens = []
                for op in insn.operands:

                    if op.type == 2:  # MEM operand type
                        # op.mem.disp is displacement, effective address approx.
                        addr = op.mem.disp
                        if addr in const_map:
                            type_str, val = const_map[addr]
                            tokens.append(f"{type_str}({val})")
                        else:
                            tokens.append(f"MEM[0x{addr:x}]")
                    elif op.type == 1:  # IMM
                        tokens.append(f"IMM({op.imm})")
                    else:
                        tokens.append(insn.op_str)
                print(f"{insn.mnemonic} {' '.join(tokens)}")

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
                blocks = [b.strip() for b in ldis_text.split('|')]
                result[funcname] = blocks
    return result

def get_loaded_memory_ranges(proj):
    """
    Returns a list of tuples (start_addr, end_addr) for each loaded section.
    """
    ranges = []
    for section in proj.loader.main_object.sections:
        #if section.is_loaded:
        #    start = section.vaddr
        #    end = start + section.memsize
        #    ranges.append((start, end))
        pass
    return ranges

def is_address(addr, addr_ranges):
    for start, end in addr_ranges:
        if start <= addr < end:
            return True
    return False    

def register_block_name(id: int) -> str:
    """
    Creates tokens for blocks.
    Block number < 16: Block0 - BlockF
    Block number > 16: BlockLitStart BlockLit1 BlockLit0 BlockLitEnd
    """
    block_name: str = "Block"
    if id < 16:
        block_name += f"{str(hex(id)[2:]).upper()}"
    else:
        binary_list = list(bin(id)[2:])
        block_name = "BlockLitStart"
        for element in binary_list:
            block_name += f" BlockLit{element}"
        block_name += " BlockLitEnd"
    return block_name


def lowlevel_disas(cfg, constant_list) -> dict:
    """
    Operand types: (in theory)
    0: Register         mov eax, ebx          ; reg (eax), reg (ebx)        => operands are registers (type 0)
    1: Immediate        add eax, 5            ; reg (eax), imm (5)           => one register, one immediate (type 1)
    2: Memory           mov eax, [ebx + 4]    ; reg (eax), mem ([ebx+4])    => register and memory operand (type 2)
    3: FloatingPoint    fld qword ptr [esp]   ; floating point load from mem => mem (type 2) with floating point semantics (type 3)

    Operand types (inferred from code due to terrible documentation from angr)
    1: Register
    2: Immediate
    3: Memory

    Classifies:
    - ValueConstants: 0x00 to 0xFF
    - ValueConstantLiterals: larger static values (up to 128-bit)
    - OpaqueConstants: memory references using base registers or unresolved values
    - OpaqueConstantLiterals: overflow beyond the first 16 unique opaque constants
    """
    func_disas = {}

    for func_addr, func in cfg.functions.items():
        if func.name in ['UnresolvableCallTarget', 'UnresolvableJumpTarget']:
            continue

        #print("\n")
        func_name = cfg.functions[func_addr].name
        index = (func_name, hex(func_addr))
        temp_bbs = []

        value_constants = {}
        value_constant_literals_candidates = {}

        block_counter = 0
        for block in func.blocks:
            #print(register_block_name(block_counter))
            block_addr = hex(block.addr)

            disassembly_list = []
            
            # Single loop over instructions to get both disassembly and immediates
            for insn in block.capstone.insns:
                insn_list = []
                if hasattr(insn, 'operands'):
                    #print("\n")
                    # go through all operands
                    for op in insn.operands:
                        insn_list.append(op.type)
                        if op.type == 0 or op.type > 3:
                            print("WHAAAAAAAAAAAAAAAAAAAAAT")
                            raise Exception
                        if op.type == 1: # REGISTER
                            #print(f"REGISTER: {insn.reg_name(op.reg)}")
                            # TODO add to tokenizer
                            pass
                        elif op.type == 2: # IMMEDIATE 
                            imm_val = op.imm
                            #print(f"IMMEDIATE {hex(imm_val)}")
                            if 0x00 <= imm_val <= 0xFF:
                                if hex(imm_val) in value_constants:
                                    value_constants[hex(imm_val)] += 1
                                else:
                                    value_constants[hex(imm_val)] = 1
                            elif 0x100 <= imm_val <= (2**128 - 1):
                                if hex(imm_val) in value_constant_literals_candidates:
                                    value_constant_literals_candidates[hex(imm_val)] += 1
                                else:
                                    value_constant_literals_candidates[hex(imm_val)] = 1
                        elif op.type == 3: # MEMORY
                            base = insn.reg_name(op.mem.base) if op.mem.base != 0 else None
                            index = insn.reg_name(op.mem.index) if op.mem.index != 0 else None
                            scale = op.mem.scale
                            disp = op.mem.disp
                            op_type: str
                            if op.size == 1:
                                op_type = "byte ptr"
                            elif op.size == 2:
                                op_type = "word ptr"
                            elif op.size == 4:
                                op_type = "dword ptr"
                            elif op.size == 8:
                                op_type = "qword ptr"
                            print(f"Memory operand: base={base}, index={index}, scale={scale}, disp={hex(disp)}, type={op_type}")
                            disp = abs(disp)
                            if 0x00 <= disp <= 0xFF:
                                if hex(disp) in value_constants:
                                    value_constants[hex(disp)] += 1
                                else:
                                    value_constants[hex(disp)] = 1
                            elif 0x100 <= disp <= (2**128 - 1):
                                if hex(disp) in value_constant_literals_candidates:
                                    value_constant_literals_candidates[hex(disp)] += 1
                                else:
                                    value_constant_literals_candidates[hex(disp)] = 1
                            print(insn.mnemonic, insn.op_str)
                            # TODO check what to do with negative offset

                                
                #print((insn.mnemonic, insn.op_str))
                #print(f"Operand types: {insn_list}")
                disassembly_list.append((insn.mnemonic, insn.op_str))
                if insn.mnemonic == "call":
                    print((insn.mnemonic, insn.op_str))
            
            temp_bbs.append([block_addr, disassembly_list])
            block_counter += 1


        # handle the constants dict
        # VALUE CONSTANTS 0x00 bis 0xFF
        #sorted_value_constants = dict(sorted(value_constants.items(), key=lambda item: item[1], reverse=True))
        sorted_value_constants = value_constants
        renamed_value_constants = name_value_constants(sorted_value_constants)
        print(f"\nValue Constants")
        for key, value in renamed_value_constants.items():
            print(f"{key}, {value}")
            pass
        
        # Take all candidates for value constant literals and check which of those are known constants
        # First, sort the items once
        sorted_items = sorted(value_constant_literals_candidates.items(), key=lambda item: item[1], reverse=True)

        # Then, iterate once and split into matching and non-matching
        matching = {}
        non_matching = {}
        for k, v in sorted_items:
            if k in constant_list:
                matching[k] = v
            else:
                non_matching[k] = v


        sorted_matching = dict(sorted(matching.items(), key= lambda item: item[1], reverse=True))
        sorted_non_matching = dict(sorted(non_matching.items(), key= lambda item: item[1], reverse=True))
        value_constant_literals = name_value_constant_literals(sorted_matching)
        print("Value Constant Literals")
        for key, value in value_constant_literals.items():
            print(f"{key}, {value}")
            pass
        
        opaque_constants, opaque_constant_literals = name_opaque_constants(sorted_non_matching)
        print("Opaque Constants")
        for key, value in opaque_constants.items():
            print(f"{key}, {value}")
            pass
        print("Opaque Constant Literals")
        for key, value in opaque_constant_literals.items():
            print(f"{key}, {value}")
            pass
        if matching:
            break


        #print(f"Temp bbs: {temp_bbs}")
        #print(f"Sorted subset: {sorted_subset}")

        func_disas[index] = temp_bbs
    return func_disas

"""
    - ValueConstants: 0x00 to 0xFF
    - ValueConstantLiterals: larger static values (up to 128-bit)
    - OpaqueConstants: memory references using base registers or unresolved values
    - OpaqueConstantLiterals: overflow beyond the first 16 unique opaque constants
"""

def name_opaque_constants(occ: dict) -> tuple[dict[str, tuple[str, int]], dict[str, tuple[str, int]]]:
    """
    Takes a dict of all addresses that do not point to a known constant. Assigns the first 16 to OPAQUE_CONSTANTS, the rest to OPAQUE_CONSTANT_LITERALS
    
    Args:
        occ (dict[address, occurence])

    Returns:
        Tuple(dict[const_name: tuple(address, occurence)], dict[const_name: tuple(address, occurence)])
    
    
    
    """
    arch_name = "x86"
    counter = 0
    opaque_constants = {}
    opaque_constant_literals = {}
    for addr, freq in occ.items():
        if counter < 16:
            new_name = f"{arch_name}_OP_CONST_{counter}"
            opaque_constants[new_name] = (addr, freq)
        else:
            new_name = f"{arch_name}_OP_CONST_LIT_{counter}"
            opaque_constant_literals[new_name] = (addr, freq)
        counter += 1
    return opaque_constants, opaque_constant_literals


def name_value_constant_literals(vcl: dict) -> dict[str, tuple[str, int]]:
    """
    Takes a sorted dict of value constant literals and gives them a descriptive token name: e.g. 0x7c --> x86_VALCONST_124

    Args:
        vc (dict): Previously sorted dict of hex value constant literals and their number of occurences within a function.

    Returns:
        renamed_dict (dict): Mapping from new constant name to tuple of value constant literal: occurences.
    """
    arch_name = "x86"
    renamed_dict = {}
    counter = 0
    for (addr, freq) in vcl.items():
        new_name = f"{arch_name}_VAL_CONST_LIT_{counter}"
        renamed_dict[new_name] = (addr, freq)
        counter += 1
    return renamed_dict


def name_value_constants(vc: dict) -> dict[str, tuple[str, int]]:
    """
    Takes a sorted dict of value constants and gives them a descriptive token name: e.g. 0x7c --> x86_VALCONST_124

    Args:
        vc (dict): Previously sorted dict of hex value constants and their number of occurences within a function.

    Returns:
        renamed_dict (dict): Mapping from new constant name to tuple of value constant : occurences.
    """
    arch_name = "x86"
    renamed_dict = {}
    for (addr, freq) in vc.items():
        new_name = f"{arch_name}_VAL_CONST_{int(addr, 16)}"
        renamed_dict[new_name] = (addr, freq)
    return renamed_dict


def parse_and_save_data_sections(proj, output_txt='parsed_data.txt'):
    sections_to_parse = ['.rodata', '.data', '.data.rel.ro']
    all_entries = []
    addr_dict = {}

    def parse_rodata(data, base_addr):
        entries = []
        # ASCII strings ≥4 chars + null terminator
        for match in re.finditer(b'[\x20-\x7e]{4,}\x00', data):
            s = match.group().rstrip(b'\x00').decode('utf-8', errors='ignore')
            addr = base_addr + match.start()
            entries.append({'section': '.rodata', 'start': hex(addr), 'end': hex(addr + len(s) + 1), 'value': f'"{s}"'})
        return entries

    def parse_data(data, base_addr, word_size=4, section_name=''):
        entries = []
        for i in range(0, len(data), word_size):
            chunk = data[i:i+word_size]
            if len(chunk) < word_size:
                continue
            val = int.from_bytes(chunk, byteorder='little')
            entries.append({'section': section_name, 'start': hex(base_addr + i), 'end': hex(base_addr + i + word_size), 'value': hex(val)})
        return entries

    for sec in proj.loader.main_object.sections:
        if sec.name not in sections_to_parse:
            continue
        start = sec.vaddr
        size = sec.memsize
        data = proj.loader.memory.load(start, size)

        if sec.name == '.rodata':
            entries = parse_rodata(data, start)
        elif sec.name in ['.data', '.data.rel.ro']:
            entries = parse_data(data, start, 4, sec.name)
        else:
            entries = []

        all_entries.extend(entries)
        for e in entries:
            addr_dict[e['start']] = [e['end'], e['section'], e['value']]

    with open(output_txt, 'w') as f:
        for e in all_entries:
            f.write(f"{e['section']}, {e['start']} - {e['end']}: {e['value']}\n")

    print(f"Parsed {len(all_entries)} entries from sections {sections_to_parse} and saved to {output_txt}")
    return addr_dict


def main():
    file_path = "src/clamav/x86-gcc-9-O3_clambc"
    #print(extract_ldis_blocks_from_file("out\\clamav\\x86-gcc-4.8-Os_clambc\\x86-gcc-4.8-Os_clambc_functions.csv"))
    
    project = angr.Project("src/curl/x86-clang-3.5-O0_curl", auto_load_libs=False)
    section_data = parse_and_save_data_sections(project)
    print(section_data)
    
    #const_map = build_constant_map(project)
    #annotate_disassembly_with_constants(project, const_map)
    cfg = project.analyses.CFGFast(normalize=True)
    d: dict = lowlevel_disas(cfg, section_data)
    with open("test.txt", encoding="utf-8", mode="w") as f:
        f.write("Function name, function address, assembly")
        for key, value in d.items():
            f.write(f"{key}: {value}\n")    
    return
    function_bbs = {}
    string_map = {}
    iter = 0
    obj = project.loader.main_object
    # --- STRING MAP (From .rodata or readable segments)
    # --- STRING MAP ---
    # Search readable sections in the main binary
    for section in obj.sections:
        if section.name in [".rodata", ".data", ".data.rel.ro"]:
            print(f"{section.name}: vaddr=0x{section.vaddr:x}, size=0x{section.memsize:x}")
            data = project.loader.memory.load(section.vaddr, section.memsize)
            print(f"{section.name} non-zero bytes:", sum(b != 0 for b in data))
            print(f"{section.name} total bytes:", len(data))
            data = project.loader.memory.load(section.vaddr, section.memsize)
            print(f"Dumping first 64 bytes of {section.name}:")
            print(data[:64].hex(' '))
            try:
                data = project.loader.memory.load(section.vaddr, section.memsize)
            except Exception:
                continue
            
            string_map = {}  # Hier neu initialisieren, für jede Sektion separat

            base = section.vaddr
            for match in re.finditer(rb"[ -~]{4,}", data):
                string_val = match.group().decode(errors="ignore")
                addr = base + match.start()
                string_map[addr] = string_val
            
            with open(f"{section.name}.txt", encoding="utf-8", mode="w") as f:
                for address, string in string_map.items():
                    f.write(f"{hex(address)}: \"{string}\"\n")
    return



    for func_addr, func in cfg.functions.items():
        if iter == 100:
            break
        if func.name.startswith('sub_') or func.name in ['UnresolvableCallTarget', 'UnresolvableJumpTarget']:
            continue
        temp_bbs = {}
        for block in func.blocks:
            block_addr = block.addr
            disassembly = block.capstone.insns
            #print(disassembly)
            disassembly_list = [(insn.mnemonic, insn.op_str) for insn in disassembly]
            print(disassembly_list)
            temp_bbs[hex(block_addr)] = disassembly_list
        function_bbs[func_addr] = temp_bbs
        iter += 1
    #print(function_bbs)

if __name__ == "__main__":
    main()