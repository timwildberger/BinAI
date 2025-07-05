def resolve_metadata(dict1, dict2, metadata_dict, placeholder=('UNKNOWN', -1), key_index=2) -> list[
    tuple[str, str, str, str, str]]:
    """
    Matches addresses from dict1 and dict2 with metadata_dict using exact and range matching.

    :param dict1: dict mapping address to token name
    :param dict2: same as dict1
    :param metadata_dict: dict mapping address to metadata tuple (token_name, range_end, ...)
    :param placeholder: tuple to use when no match is found
    :param key_index: index in metadata tuple that holds the end address
    :return: list of metadata tuples (either matched or placeholder)
    """
    result: list[tuple[str, str, str, str, str]] = []
    addresses = set(dict1.keys()) | set(dict2.keys())

    for addr in addresses:
        if addr in metadata_dict:
            result.append(metadata_dict[addr])
        else:
            # Try range match
            match_found = False
            for base_addr, meta in metadata_dict.items():
                try:
                    range_end = int(meta[key_index], 16) if isinstance(meta[key_index], str) else meta[key_index]
                    if int(base_addr, 16) <= int(addr, 16) <= range_end:
                        result.append(meta)
                        match_found = True
                        break
                except (IndexError, ValueError, TypeError):
                    continue
            if not match_found:
                result.append(placeholder)
    return result
