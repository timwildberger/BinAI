import re

import numpy as np

from tokenizer.function_token_list import FunctionTokenList
from tokenizer.patterns import MemCloseBracket, OpaqueConst, MemOpenBracket, InsnPointerLengths, Maybe, InsnNop, Multi, \
    InsnPrefixes, InsnControlFlow, BlockDef, Block, MemPlus, ValuedConst, InsnRegistry
from tokenizer.patterns.matcher import TokenPattern
from tokenizer.token_manager import VocabularyManager


class FunctionFilter:
    def __init__(self):
        # TokenPattern for a jump-only function:
        # Block_Def, Block(0), [RepeatType.MAYBE, PlatformInstructionTypes.PREFIXES], PlatformInstructionTypes.CONTROL_FLOW,
        # [RepeatType.MAYBE, PlatformInstructionTypes.POINTER_LENGTHS], MemoryOperandSymbol.OPEN_BRACKET,
        # PlatformInstructionTypes.OTHER, MemoryOperandSymbol.CLOSE_BRACKET
        self.jump_only_pattern = TokenPattern(BlockDef, Block + 0, Maybe + InsnPrefixes, InsnControlFlow,
                                              Maybe + InsnPointerLengths, MemOpenBracket,
                                              Maybe + [InsnRegistry, MemPlus],
                                              (OpaqueConst + 0) | ValuedConst,
                                              MemCloseBracket)
        self.nop_only_pattern = TokenPattern(Maybe + InsnPrefixes, Multi + InsnNop, Maybe + [Maybe + InsnPointerLengths, MemOpenBracket, OpaqueConst + 0, MemCloseBracket])




    def filter_fns(self, fn_tokens: FunctionTokenList, func_name, vm: VocabularyManager) -> bool:
        """Returns true if function contains only one jump instruction.
        → Remove 'nop' (single and repetitions)
        → Remove "hlt
        """"""
        if len(block_run_lengths) > 1:
            return False
        """
        if fn_tokens.block_count > 1:
            return False


        if self.jump_only_pattern.match(fn_tokens.iter_raw_tokens(), vm):
            print(f"\nREMOVED {func_name}: {fn_tokens.to_asm_original()} / {fn_tokens.to_asm_like()}")


        if self.nop_only_pattern.match(fn_tokens.iter_raw_tokens(), vm):
            print(f"\nREMOVED {func_name}: {fn_tokens.to_asm_original()} / {fn_tokens.to_asm_like()}")

        # remove nop only and hlt
        if fn_tokens.block_count == 1:
            arr = fn_tokens.insn_strs[1:fn_tokens.last_index]

            allowed = ["nop ", "hlt ", "ret "]
            is_padding = np.isin(arr, allowed)

            if np.all(is_padding):
                print(f"\nREMOVED {func_name}: {fn_tokens.to_asm_original()} / {fn_tokens.to_asm_like()}")

        # insn_mask = np.array([2, 7])
        # if insn_run_lengths.shape == (2,):
        #     if np.array_equal(insn_mask.flatten(), insn_run_lengths):
        #         jmp_indirect_pattern = re.compile(
        #             r'^jmp\s+'
        #             r'(?:[a-z]{1,8}word\s+)?'  # optional size prefix like dword/qword/xmmword
        #             r'ptr\s*'
        #             r'\[\s*[^]]+\s*\]$',  # everything inside brackets, anything except ]
        #             re.IGNORECASE
        #         )
        #         if str(fn_tokens.insn_strs[1]).split(" ")[0] in instr_sets.addressing_control_flow:
        #             print(f"\nREMOVED {func_name}: {fn_tokens.insn_strs}")
        #             return True

        return False


# --- TESTS ---

