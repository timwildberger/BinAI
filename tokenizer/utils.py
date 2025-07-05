def register_name_range(id: int, basename: str) -> str:
    """
    Creates tokens for blocks.
    Block number < 16: Block_0 - Block_F
    Block number > 16: Block_Lit_Start Block_Lit_1 Block_Lit_0 Block_Lit_End
    """

    """
    Creates tokens for block indexes.
    Block number < 255: Block_0 -  Block_F
    Block number > 255: Block_Lit_Start Block_{HEX VALUE} Block_{HEX VALUE} Block_Lit_End"""
    
    id_str = hex(id)[2:].upper()
    chunks = [id_str[i: i+2] for i in range(0, len(id_str), 2)]
    name = f"{basename}_Lit_Start"
    for element in chunks:
        name += f" {basename}_{element}"
    name += f" {basename}_Lit_End"
    return name


