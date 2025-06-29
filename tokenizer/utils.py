def register_name_range(id: int, basename: str) -> str:
    """
    Creates tokens for blocks.
    Block number < 16: Block0 - BlockF
    Block number > 16: Block_Lit_Start Block_Lit_1 Block_Lit_0 Block_Lit_End
    """

    """
    Creates tokens for block indexes.
    Block number < 255: Block0 -  BlockF
    Block number > 255: BlockLitStart BlockLit{HEX VALUE} BlockLit{HEX VALUE} BlockLitEnd"""
    if id < 16:
        name = f"{basename}_{str(hex(id)[2:]).upper()}"
    else:
        id_str = hex(id)[2:].upper()
        chunks = [id_str[i] for i in range(0, len(id_str), 2)]
        name = f"{basename}_Start"
        for element in chunks:
            name += f" {basename}_{element}"
        name += f" {basename}_End"
    return name

def register_value_in_dict(dict: dict, value: str) -> dict:
    if value not in dict:
        dict[value] = 1
    else:
        dict[value] += 1
    return dict
