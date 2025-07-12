from tokenizer.architecture import PlatformInstructionTypes
from tokenizer.token_pattern import TokenPattern, RepeatType
from tokenizer.tokens import MemoryOperandSymbol, TokenType


def test_jump_only_pattern():
    from tokenizer.token_manager import VocabularyManager

    vm = VocabularyManager("x86")

    # Create a correct jump-only token sequence
    tokens = [
        vm.Block_Def(),
        vm.Block(0),
        vm.PlatformToken("jmp", PlatformInstructionTypes.CONTROL_FLOW),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(0),
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]

    # Should match (no prefix, no pointer type)
    pattern = TokenPattern(
        TokenType.BLOCK_DEF,
        TokenType.BLOCK,
        (RepeatType.MAYBE, PlatformInstructionTypes.PREFIXES),
        PlatformInstructionTypes.CONTROL_FLOW,
        (RepeatType.MAYBE, PlatformInstructionTypes.POINTER_LENGTHS),
        MemoryOperandSymbol.OPEN_BRACKET,
        TokenType.OPAQUE_CONST,
        MemoryOperandSymbol.CLOSE_BRACKET
    )
    assert pattern.match(iter(tokens), vm), "Correct jump-only pattern should match"

    # Add a prefix token (should still match)
    tokens_prefix = [
        vm.Block_Def(),
        vm.Block(0),
        vm.PlatformToken("rep", PlatformInstructionTypes.PREFIXES),
        vm.PlatformToken("jmp", PlatformInstructionTypes.CONTROL_FLOW),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(0),
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]
    assert pattern.match(iter(tokens_prefix), vm), "Jump-only pattern with prefix should match"

    # Add a pointer type token (should still match)
    tokens_ptr = [
        vm.Block_Def(),
        vm.Block(0),
        vm.PlatformToken("jmp", PlatformInstructionTypes.CONTROL_FLOW),
        vm.PlatformToken("dword", PlatformInstructionTypes.POINTER_LENGTHS),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(0),
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]
    assert pattern.match(iter(tokens_ptr), vm), "Jump-only pattern with pointer type should match"

    # Wrong: missing CONTROL_FLOW
    tokens_wrong = [
        vm.Block_Def(),
        vm.Block(0),
        vm.PlatformToken("nop", PlatformInstructionTypes.NOP),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(0),
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]
    assert not pattern.match(iter(tokens_wrong), vm), "Pattern missing CONTROL_FLOW should not match"

    # Wrong: extra token at end
    tokens_extra = tokens + [vm.PlatformToken("nop", PlatformInstructionTypes.NOP)]
    assert not pattern.match(iter(tokens_extra), vm), "Pattern with extra token should not match"

    # Wrong: missing bracket
    tokens_missing_bracket = tokens[:-1]
    assert not pattern.match(iter(tokens_missing_bracket), vm), "Pattern missing closing bracket should not match"

    print("All jump_only_pattern tests passed.")


if __name__ == "__main__":
    test_jump_only_pattern()
