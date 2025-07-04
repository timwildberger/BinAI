from tokenizer.tokens import VocabularyManager, TokenResolver


def name_opaque_constants(
        occ: dict, base_name: str, vocab_manager: VocabularyManager, resolver: TokenResolver
) -> tuple[dict[str, tuple["VocabularyManager.Opaque_Const", int]], dict[str, tuple["VocabularyManager.Opaque_Const", int]]]:
    """
    Takes a dict of all addresses that do not point to a known constant. Assigns the first 16 to OPAQUE_CONSTANTS, the rest to OPAQUE_CONSTANT_LITERALS

    Args:
        occ (dict[address, occurence])
        base_name (str): Base name for the constants
        vocab_manager (VocabularyManager): Vocabulary manager for token creation
        resolver (TokenResolver): Token resolver for ID generation

    Returns:
        tuple(dict[const_name: tuple(Opaque_Const, occurence)], dict[const_name: tuple(Opaque_Const, occurence)])
    """
    counter = 0
    opaque_constants = {}
    opaque_constant_literals = {}
    for addr, freq in occ.items():
        opaque_id = resolver.get_opaque_id(addr)
        opaque_const = vocab_manager.Opaque_Const(opaque_id)

        if counter < 16:
            opaque_constants[addr] = (opaque_const, freq)
        else:
            opaque_constant_literals[addr] = (opaque_const, freq)
        counter += 1
    return opaque_constants, opaque_constant_literals


def name_value_constant_literals(
        vcl: dict, base_name: str, vocab_manager: VocabularyManager
) -> dict[str, tuple["VocabularyManager.Valued_Const", int]]:
    """
    Takes a sorted dict of value constant literals and gives them a descriptive token name: e.g. 0x7c --> x86_VALCONST_124

    Args:
        vcl (dict): Previously sorted dict of hex value constant literals and their number of occurences within a function.
        base_name (str): Base name for the constants
        vocab_manager (VocabularyManager): Vocabulary manager for token creation

    Returns:
        renamed_dict (dict): Mapping from address to Valued_Const token objects.
    """
    renamed_dict = {}
    for addr, freq in vcl.items():
        value_const = vocab_manager.Valued_Const(int(addr, 16))
        renamed_dict[addr] = (value_const, freq)
    return renamed_dict


def name_value_constants(vc: dict, vocab_manager: VocabularyManager) -> dict[
    str, tuple["VocabularyManager.Valued_Const", int]]:
    """
    Takes a sorted dict of value constants and gives them a descriptive token name: e.g. 0x7c --> x86_VALCONST_124

    Args:
        vc (dict): Previously sorted dict of hex value constants and their number of occurences within a function.
        vocab_manager (VocabularyManager): Vocabulary manager for token creation

    Returns:
        renamed_dict (dict): Mapping from address to Valued_Const token objects.
    """
    renamed_dict = {}
    for addr, freq in vc.items():
        # print(f"INTEGER: {int(addr, 16)}, HEX: {addr[2:]}")
        value_const = vocab_manager.Valued_Const(int(addr, 16))
        renamed_dict[addr] = (value_const, freq)
    return renamed_dict
