import re


def parse_instruction(
        ins_dict,
        renamed_value_constants,
        value_constant_literals,
        opaque_constants,
        opaque_constant_literals,
        mnemonics,
        inv_prefix_tokens,
        symbol_tokens,
        func_addr_range: list,
) -> str:
    """
    Tokenizes a single instruction dictionary into prefix, mnemonic, and operand tokens.

    Args:
        ins_dict (dict): {
            'mnemonic': str,
            'op_str': str,
            'prefixes': list[str]  # e.g., ['x86_lock']
        }
        renamed_value_constants (dict[str, int]): Mapping from address to Tokenname
        value_constant_literals: dict
        opaque_constants: dict
        opaque_constant_literals: dict
        mnemonics: dict of mnemonic -> token
        symbol_tokens: dict of symbol (register, prefix, etc.) -> token

    Returns:
        str: space-separated tokenized instruction
    """
    SIZE_SPECIFIERS = {
        "byte": "x86_BYTE_PTR",
        "word": "x86_WORD_PTR",
        "dword": "x86_DWORD_PTR",
        "qword": "x86_QWORD_PTR",
        "xmmword": "x86_XMMWORD_PTR",
        "ymmword": "x86_YMMWORD_PTR",
        "zmmword": "x86_ZMMWORD_PTR",
        "tmmword": "x86_ZMMWORD_PTR",
    }

    mnemonic = ins_dict[0]
    op_str = ins_dict[1]
    prefixes = ins_dict[2]

    token_lst = []

    # Add mnemonic token
    if mnemonic in mnemonics:
        mnemonic_token = mnemonics[mnemonic]
        if isinstance(mnemonic_token, Tokens):
            token_lst.append(mnemonic_token.to_string())
        else:
            token_lst.append(str(mnemonic_token))
    else:
        raise ValueError(f"Mnemonic {mnemonic} has not been registered.")

    # Handle operands
    if op_str:
        operand = op_str.split(", ")

        for i in range(len(operand)):
            current_operand = operand[i]

            # Handle ljmp-style segment:offset operands (e.g., "0x9c23:0xeaafaf45")
            if ":" in current_operand and all(part.startswith("0x") for part in current_operand.split(":")):
                segment, offset = current_operand.split(":")

                try:
                    seg_val = resolve_constant(
                        segment,
                        renamed_value_constants,
                        value_constant_literals,
                        opaque_constants,
                        opaque_constant_literals,
                        func_addr_range,
                    )
                    off_val = resolve_constant(
                        offset,
                        renamed_value_constants,
                        value_constant_literals,
                        opaque_constants,
                        opaque_constant_literals,
                        func_addr_range,
                    )
                except:
                    print(f"{mnemonic}, {op_str}")
                    raise ValueError

                processed = [seg_val, ":", off_val]  # Keep ":" as is or replace if needed
                token_lst.extend(processed)
                continue  # Skip rest of loop, already handled

            symbols = re.split(r"([0-9A-Za-z_:]+)", operand[i])
            symbols = [s.strip() for s in symbols if s]
            processed = []
            for s in symbols:
                if (
                        s.lower() == "ptr" or s.lower() in inv_prefix_tokens.values()
                ):  # skip token solely reserved to make code more human-readable
                    continue  # skip ptr entirely
                if s.startswith("0x"):  # hex constants
                    try:
                        v = resolve_constant(
                            s,
                            renamed_value_constants,
                            value_constant_literals,
                            opaque_constants,
                            opaque_constant_literals,
                            func_addr_range,
                        )
                    except:
                        print(f"{mnemonic}, {op_str}")
                        raise ValueError
                    processed.append(v)
                elif s.isdigit():  # byte constants
                    try:
                        v = resolve_constant(
                            hex(int(s)),
                            renamed_value_constants,
                            value_constant_literals,
                            opaque_constants,
                            opaque_constant_literals,
                            func_addr_range,
                        )
                    except:
                        print(f"{mnemonic}, {op_str}")
                        raise ValueError

                    processed.append(v)
                elif s in SIZE_SPECIFIERS.keys():
                    processed.append(SIZE_SPECIFIERS[s])
                elif s in symbol_tokens:
                    processed.append(symbol_tokens[s])
                else:
                    processed.append(s)

            token_lst.extend(processed)
    return " ".join(token_lst)


def resolve_constant(
        s,
        renamed_value_constants,
        value_constant_literals,
        opaque_constants,
        opaque_constant_literals,
        func_addr_range: list[dict[int, tuple[str, str]]],
):
    """
    Returns the tokenrepresentation depending on the data type.

    Args:
        s (str): The element of the disassembly stream that is to be converted to a token
        renamed_value_constants (dict[str, tuple[str, int]]): dict with all positive value constant tokens
        value_constant_literals (dict[str, int]): dict with all valued constant literals tokens
        opaque_constants (dict[str, int]): dict with all opaque constants tokens
        opaque_constant_literals (dict[str, int]): dict with all opaque constant literals tokens

    Returns:
        token (str)
    """
    for element in func_addr_range:
        for block_nr, bounds in element.items():
            try:
                if int(bounds[0], 16) <= int(s, 16) < int(bounds[1], 16):
                    return block_nr
            except:
                print(s)
                raise ValueError
    return (
            renamed_value_constants.get(s, [None])[0]
            or value_constant_literals.get(s, [None])[0]
            or opaque_constants.get(s, [None])[0]
            or opaque_constant_literals.get(s, [None])[0]
            or f"UNBEKNOWNST: {s}"
    )
