from tokenizer.architecture import PlatformInstructionTypes
from tokenizer.patterns import *
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


    pattern = TokenPattern(BlockDef, Block + 0, Maybe + InsnPrefixes, InsnControlFlow, Maybe + InsnPointerLengths, MemOpenBracket, OpaqueConst + 0, MemCloseBracket)

    print(f"Testing jump_only_pattern: {pattern}")

    # pattern = TokenPattern(
    #     TokenType.BLOCK_DEF,
    #     TokenType.BLOCK,
    #     (RepeatType.MAYBE, PlatformInstructionTypes.PREFIXES),
    #     PlatformInstructionTypes.CONTROL_FLOW,
    #     (RepeatType.MAYBE, PlatformInstructionTypes.POINTER_LENGTHS),
    #     MemoryOperandSymbol.OPEN_BRACKET,
    #     TokenType.OPAQUE_CONST,
    #     MemoryOperandSymbol.CLOSE_BRACKET
    # )

    # Should match (no prefix, no pointer type)
    if not pattern.match(iter(tokens), vm, True):
        raise AssertionError(f"Correct jump-only pattern should match: {pattern.get_error()}") from pattern.get_error()

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
    if not pattern.match(iter(tokens_prefix), vm, True):
        raise AssertionError(f"Jump-only pattern with prefix should match: {pattern.get_error()}") from pattern.get_error()

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
    if not pattern.match(iter(tokens_ptr), vm, True):
        raise AssertionError(f"Jump-only pattern with pointer type should match: {pattern.get_error()}") from pattern.get_error()

    # Wrong: missing CONTROL_FLOW
    tokens_wrong = [
        vm.Block_Def(),
        vm.Block(0),
        vm.PlatformToken("nop", PlatformInstructionTypes.NOP),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(0),
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]
    if pattern.match(iter(tokens_wrong), vm):
        raise AssertionError(f"Pattern missing CONTROL_FLOW should not match: {pattern.get_error()}")

    # Wrong: extra token at end
    tokens_extra = tokens + [vm.PlatformToken("nop", PlatformInstructionTypes.NOP)]
    if pattern.match(iter(tokens_extra), vm,):
        raise AssertionError(f"Pattern with extra token should not match: {pattern.get_error()}")

    # Wrong: missing bracket
    tokens_missing_bracket = tokens[:-1]
    if pattern.match(iter(tokens_missing_bracket), vm):
        raise AssertionError(f"Pattern missing closing bracket should not match: {pattern.get_error()}")

    # Wrong: wrong block id
    tokens_wrong_block = [
        vm.Block_Def(),
        vm.Block(1),  # Should be 0
        vm.PlatformToken("jmp", PlatformInstructionTypes.CONTROL_FLOW),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(0),
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]
    if pattern.match(iter(tokens_wrong_block), vm):
        raise AssertionError(f"Pattern with wrong block id should not match: {pattern.get_error()}")

    # Wrong: wrong opaque const value
    tokens_wrong_opaque = [
        vm.Block_Def(),
        vm.Block(0),
        vm.PlatformToken("jmp", PlatformInstructionTypes.CONTROL_FLOW),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(42),  # Should be 0
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]
    if pattern.match(iter(tokens_wrong_opaque), vm):
        raise AssertionError(f"Pattern with wrong opaque const should not match: {pattern.get_error()}")

    # Wrong: wrong prefix type
    tokens_wrong_prefix = [
        vm.Block_Def(),
        vm.Block(0),
        vm.PlatformToken("nop", PlatformInstructionTypes.NOP),  # Should be PREFIXES
        vm.PlatformToken("jmp", PlatformInstructionTypes.CONTROL_FLOW),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(0),
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]
    if pattern.match(iter(tokens_wrong_prefix), vm):
        raise AssertionError(f"Pattern with wrong prefix type should not match: {pattern.get_error()}")

    print("All jump_only_pattern tests passed.")


if __name__ == "__main__":
    test_jump_only_pattern()
