import angr
import re
import csv
from pathlib import Path
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


def lowlevel_disas(cfg):
    """
    Operand types:
    0: Register
    1: Immediate
    2: Memory
    3: FloatingPoint

    ValueConstants (00 to FF representing a constant of exactly that value
    ValueConstantLiterals (for up to 128 bit values) 
    OpaqueConstants (16 unique - they represent an opaque value basically for example the representation of the string "HelloWorld" ) 
    OpaqueConstantLiterals (if a function needs more that 16 OpaqueConstants)
    """
    func_disas = {}
    token_register = {}
    for func_addr, func in cfg.functions.items():
        if func.name in ['UnresolvableCallTarget', 'UnresolvableJumpTarget']:
            continue
        print("\n")
        func_name = cfg.functions[func_addr].name
        index = (func_name, hex(func_addr))
        temp_bbs = []
        value_constants = {}
        value_constant_literals = {}

        block_counter = 0
        for block in func.blocks:
            #print(register_block_name(block_counter))
            block_addr = hex(block.addr)

            disassembly_list = []
            token_list = []
            
            # Single loop over instructions to get both disassembly and immediates
            for insn in block.capstone.insns:
                insn_list = []
                if hasattr(insn, 'operands'):
                    # go through all operands
                    for op in insn.operands:
                        insn_list.append(op.type)
                        if op.type == 2:
                            imm_val = op.imm
                            #print(f"Immediate value: {hex(imm_val)}")
                            if 0x00 <= imm_val <= 0xFF:
                                if hex(imm_val) in value_constants:
                                    value_constants[hex(imm_val)] += 1
                                else:
                                    value_constants[hex(imm_val)] = 1
                                
                #print((insn.mnemonic, insn.op_str))
                #print(f"{insn_list}")
                disassembly_list.append((insn.mnemonic, insn.op_str))
            
            temp_bbs.append([block_addr, disassembly_list])
            block_counter += 1


        # handle the constants dict
        sorted_items = dict(sorted(value_constants.items(), key=lambda item: item[1], reverse=True))
        for key, value in sorted_items.items():
            print(f"{key}, {value}")

        func_disas[index] = temp_bbs
    return func_disas




def main():

    file_path = "src/clamav/x86-gcc-9-O3_clambc"
    #print(extract_ldis_blocks_from_file("out\\clamav\\x86-gcc-4.8-Os_clambc\\x86-gcc-4.8-Os_clambc_functions.csv"))
    
    project = angr.Project("C:\\Users\\timwi\\Documents\\Uni\\SS25\\BinAI\\BERT_repo\\src\\curl\\x86-gcc-9-O0_curl", auto_load_libs=False)
    #const_map = build_constant_map(project)
    #annotate_disassembly_with_constants(project, const_map)
    cfg = project.analyses.CFGFast(normalize=True)
    d = lowlevel_disas(cfg=cfg)
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