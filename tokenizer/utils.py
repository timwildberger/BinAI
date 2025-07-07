import numpy as np
import numpy.typing as npt

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




def CA_BArle_to_CBrle(c: npt.NDArray[np.int_], b: npt.NDArray[np.int_]) -> npt.NDArray[np.int_]:
    # we need indecies to be able to us searchsorted - require strictly increasing
    c = c.cumsum()
    b = b.cumsum()

    # right side matches cumsum the excluded ending index
    x = np.searchsorted(c, b, side='right')
    # these are indecies so we need to convert back to runlengths encoding
    b[1:] = x[1:] - x[:-1]
    return b