import angr
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


def main():
    project_main = angr.Project("src/clamav/x86-gcc-9-O3_clambc", auto_load_libs=False)
    cfg = project_main.analyses.CFGFast(normalize=True)
    function_bbs = {}
    iter = 0
    for func_addr, func in cfg.functions.items():
        if iter == 50:
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