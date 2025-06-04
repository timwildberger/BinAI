import angr
from typing import Dict
# load your project

another_test = "fauxware"

p = angr.Project('fauxware', load_options={"auto_load_libs": False})

# Create static CFG
cfg = p.analyses.CFGFast()


functions = {}
for f in p.kb.functions.values():
    func_dict = {}
    key_tuple = (hex(f.addr), f.name)

    for block in f.blocks:
        instr = []
        for ins in block.capstone.insns:
            opcode = ins.mnemonic
            operands = ins.op_str
            instr.append((opcode, operands))
        func_dict[block.addr] = instr
    
    functions[key_tuple] = func_dict


for (addr, name), blocks in functions.items():
    if "sub_" in name:
        pass
    print(f"\nFunction {name} at {addr}")
    print("=" * (len(name) + len(addr) + 14))
    for bb_addr, instrs in blocks.items():
        print(f"\n  Basic Block at {hex(bb_addr)}:")
        for opcode, operands in instrs:
            print(f"    {opcode.ljust(8)} {operands}")

# Question 1
number_of_functions: int = 0
for (addr, name), blocks in functions.items():
    if "sub_" not in name:
        number_of_functions += 1
print(f"Number of functions in fauxware: {number_of_functions}")

# Question 3
for f in p.kb.functions.values():
    for block in f.blocks:
        print(hex(block.addr))



"""
functions = {(hex function address, function name): {basic block address: [(opcode in string, operands in string), (opcode in string, operands in string), …]}}
"""