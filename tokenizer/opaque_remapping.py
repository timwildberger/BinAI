from tokenizer.token_lists import BlockTokenList
from tokenizer.token_manager import VocabularyManager
from tokenizer.tokens import Tokens, TokenType, TokenRaw

def apply_opaque_mapping(temp_bbs, opaque_mapping, constant_handler=None):
    """
    Apply opaque token mapping to replace old tokens with new sorted tokens.
    Also reorders metadata to match the new token ordering.

    Args:
        temp_bbs: List of blocks containing instruction tokens
        opaque_mapping: Dictionary mapping old opaque tokens to new sorted tokens
        constant_handler: Optional ConstantHandler to also reorder metadata

    Returns:
        Updated temp_bbs with remapped tokens
    """
    updated_bbs = []
    #todo i am very very sure we also need to reorder metadata

    for (block_addr, instruction_list) in temp_bbs:
        updated_instructions = []

        for instruction_tokens in instruction_list:
            updated_instruction = []

            for token in instruction_tokens:
                # Check if this token needs to be remapped
                if token in opaque_mapping:
                    updated_instruction.append(opaque_mapping[token])
                else:
                    updated_instruction.append(token)

            updated_instructions.append(updated_instruction)


        updated_bbs.append((block_addr, updated_instructions))

    # If constant_handler is provided, also reorder metadata
    if constant_handler is not None and opaque_mapping:
        constant_handler.reorder_metadata_for_mapping(opaque_mapping)

    return updated_bbs


def apply_opaque_mapping_raw_optimized(function_token_list, opaque_mapping, vocab_manager: VocabularyManager, constant_handler=None):
    """
    Apply opaque token mapping using raw tokens for efficiency, only resolving when necessary.

    Args:
        function_token_list: FunctionTokenList containing blocks with instruction tokens
        opaque_mapping: Dictionary mapping old opaque token IDs to new sorted token IDs
        vocab_manager: VocabularyManager for token resolution
        constant_handler: Optional ConstantHandler to also reorder metadata

    Returns:
        Updated FunctionTokenList with remapped tokens
    """


    # Create a new FunctionTokenList for the result
    updated_function = function_token_list.with_same_size(function_token_list, vocab_manager)

    # Convert opaque_mapping to work with token IDs if it's using token objects
    id_mapping = {}
    if opaque_mapping:
        for old_token, new_token in opaque_mapping.items():
            id_mapping[old_token.id] = new_token

    # Process each block in the function
    for block_idx, block in enumerate(function_token_list.iter_blocks()):
        block_addr = function_token_list.block_addrs[block_idx]

        # Create a new block for updated instructions
        updated_block = updated_function.view()

        # Process each instruction in the block
        for insn in block.iter_insn():
            updated_tokens = updated_block.view(insn.to_asm_original())

            # Use raw token iteration for efficiency
            for raw_token in insn:
                if raw_token.token_type == TokenType.OPAQUE_CONST:
                    token_ids = raw_token.get_token_ids()
                    if len(token_ids) == 1:
                        # Single opaque token, check if it needs remapping
                        value = vocab_manager.Opaque_Const.value_by_singleton_token_index(token_ids[0])
                        if value in id_mapping:
                            updated_tokens.append(id_mapping[value])
                        else:
                            # No remapping needed, use the raw token directly
                            updated_tokens.append(raw_token)
                        continue



                    # Only resolve opaque tokens when we need to check the ID
                    resolved_token = raw_token.resolve(vocab_manager)
                    if resolved_token.id in id_mapping:
                        updated_tokens.append(id_mapping[resolved_token.id ])
                    else:
                        updated_tokens.append(raw_token)
                else:
                    updated_tokens.append(raw_token)

            updated_block.add_insn(updated_tokens)

        # Add the updated block to the function
        updated_function.add_block(updated_block, block_addr)

    # If constant_handler is provided, also reorder metadata
    if constant_handler is not None and opaque_mapping:
        constant_handler.reorder_metadata_for_mapping(opaque_mapping)

    return updated_function
