import re

import numpy
import numpy as np

from tokenizer.function_token_list import FunctionTokenList
from tokenizer.token_manager import VocabularyManager
from tokenizer.tokens import MemoryOperandSymbol


class FunctionFilter:
    def __init__(self, vm: VocabularyManager):
        self.jump_only_fn = [vm.Block_Def, vm.Block(0), vm.PlatformToken("jmp"),
                        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET), vm.Opaque_Const(0),
                        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)]


    def check_function_just_jump(self, fn_tokens: FunctionTokenList) -> bool:
        if fn_tokens.block_count > 1:
            return False

        if fn_tokens.last_index != len(self.jump_only_fn):
            return False

        for t1, t2 in zip(fn_tokens.iter_raw_tokens(), self.jump_only_fn):
            if t1 != t2:
                return False

        return True


    def filter_fns(self, fn_tokens: FunctionTokenList, func_name) -> bool:
        """Returns true if function contains only one jump instruction.
        → Remove 'nop' (single and repetitions)
        → Remove "hlt
        """"""
        if len(block_run_lengths) > 1:
            return False
        """

        if self.check_function_just_jump(fn_tokens):
            return True

        # remove nop only and hlt
        if fn_tokens.block_count == 1:
            arr = fn_tokens.insn_strs[1:fn_tokens.last_index]

            allowed = ["nop ", "hlt ", "ret "]
            is_padding = np.isin(arr, allowed)

            if np.all(is_padding):
                print(f"\nREMOVED {func_name}: {fn_tokens.insn_strs}")
                return True

        insn_mask = np.array([2, 7])
        if insn_run_lengths.shape == (2,):
            if np.array_equal(insn_mask.flatten(), insn_run_lengths):
                jmp_indirect_pattern = re.compile(
                    r'^jmp\s+'
                    r'(?:[a-z]{1,8}word\s+)?'  # optional size prefix like dword/qword/xmmword
                    r'ptr\s*'
                    r'\[\s*[^]]+\s*\]$',  # everything inside brackets, anything except ]
                    re.IGNORECASE
                )
                if str(fn_tokens.insn_strs[1]).split(" ")[0] in instr_sets.addressing_control_flow:
                    print(f"\nREMOVED {func_name}: {fn_tokens.insn_strs}")
                    return True

        return False