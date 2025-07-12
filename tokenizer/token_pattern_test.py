from tokenizer.architecture import PlatformInstructionTypes
from tokenizer.token_pattern import TokenPattern, RepeatType
from tokenizer.tokens import MemoryOperandSymbol, TokenType


def print_error_details(pattern, label):
    print(f"Error ({label}):", pattern.get_error())
    print("Trace:\n", pattern.get_error_trace())
    print("Python stacktrace:\n", pattern.get_python_trace())


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

    # FIX: Use tuples for optional elements (not separate arguments)
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

    # Should match (no prefix, no pointer type)
    if not pattern.match(iter(tokens), vm):
        print_error_details(pattern, "correct jump-only pattern")
        raise AssertionError(f"Correct jump-only pattern should match: {pattern.get_error()}\nTrace:\n{pattern.get_error_trace()}\nPython Trace:\n{pattern.get_python_trace()}")

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
    assert pattern.match(iter(tokens_prefix), vm), f"Jump-only pattern with prefix should match: {pattern.get_error()}\nTrace:\n{pattern.get_error_trace()}\nPython Trace:\n{pattern.get_python_trace()}"

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
    assert pattern.match(iter(tokens_ptr), vm), f"Jump-only pattern with pointer type should match: {pattern.get_error()}\nTrace:\n{pattern.get_error_trace()}\nPython Trace:\n{pattern.get_python_trace()}"

    # Wrong: missing CONTROL_FLOW
    tokens_wrong = [
        vm.Block_Def(),
        vm.Block(0),
        vm.PlatformToken("nop", PlatformInstructionTypes.NOP),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(0),
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]
    assert not pattern.match(iter(tokens_wrong), vm), f"Pattern missing CONTROL_FLOW should not match: {pattern.get_error()}\nTrace:\n{pattern.get_error_trace()}\nPython Trace:\n{pattern.get_python_trace()}"
    print_error_details(pattern, "missing CONTROL_FLOW")

    # Wrong: extra token at end
    tokens_extra = tokens + [vm.PlatformToken("nop", PlatformInstructionTypes.NOP)]
    assert not pattern.match(iter(tokens_extra), vm), f"Pattern with extra token should not match: {pattern.get_error()}\nTrace:\n{pattern.get_error_trace()}\nPython Trace:\n{pattern.get_python_trace()}"
    print_error_details(pattern, "extra token")

    # Wrong: missing bracket
    tokens_missing_bracket = tokens[:-1]
    assert not pattern.match(iter(tokens_missing_bracket), vm), f"Pattern missing closing bracket should not match: {pattern.get_error()}\nTrace:\n{pattern.get_error_trace()}\nPython Trace:\n{pattern.get_python_trace()}"
    print_error_details(pattern, "missing closing bracket")

    # Wrong: wrong block id
    tokens_wrong_block = [
        vm.Block_Def(),
        vm.Block(1),  # Should be 0
        vm.PlatformToken("jmp", PlatformInstructionTypes.CONTROL_FLOW),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(0),
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]
    assert not pattern.match(iter(tokens_wrong_block), vm), f"Pattern with wrong block id should not match: {pattern.get_error()}\nTrace:\n{pattern.get_error_trace()}\nPython Trace:\n{pattern.get_python_trace()}"
    print_error_details(pattern, "wrong block id")

    # Wrong: wrong opaque const value
    tokens_wrong_opaque = [
        vm.Block_Def(),
        vm.Block(0),
        vm.PlatformToken("jmp", PlatformInstructionTypes.CONTROL_FLOW),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(42),  # Should be 0
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]
    assert not pattern.match(iter(tokens_wrong_opaque), vm), f"Pattern with wrong opaque const should not match: {pattern.get_error()}\nTrace:\n{pattern.get_error_trace()}\nPython Trace:\n{pattern.get_python_trace()}"
    print_error_details(pattern, "wrong opaque const")

    # Wrong: wrong prefix type
    tokens_wrong_prefix = [
        vm.Block_Def(),
        vm.Block(0),
        vm.PlatformToken("rep", PlatformInstructionTypes.NOP),  # Should be PREFIXES
        vm.PlatformToken("jmp", PlatformInstructionTypes.CONTROL_FLOW),
        vm.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET),
        vm.Opaque_Const(0),
        vm.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET)
    ]
    assert not pattern.match(iter(tokens_wrong_prefix), vm), f"Pattern with wrong prefix type should not match: {pattern.get_error()}\nTrace:\n{pattern.get_error_trace()}\nPython Trace:\n{pattern.get_python_trace()}"
    print_error_details(pattern, "wrong prefix type")

    print("All jump_only_pattern tests passed.")


if __name__ == "__main__":
    test_jump_only_pattern()
