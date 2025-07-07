from typing import Dict, List, Tuple, Optional
from tokenizer.tokens import TokenResolver, Tokens, OpaqueConstToken, BlockToken
from tokenizer.token_manager import VocabularyManager


class ConstantHandler:
    """Handles constant value processing and token creation"""

    def __init__(self, vocab_manager: VocabularyManager, resolver: TokenResolver, constant_dict: Dict[str, List[str]]):
        self.vocab_manager = vocab_manager
        self.resolver = resolver
        self.constant_dict = constant_dict

        # Track usage counts for constants
        self.opaque_const_usage: Dict[str, int] = {}

        # Track created tokens by their original hex value
        self.opaque_const_tokens: Dict[str, Tokens] = {}

        # Track metadata for opaque constants
        self.opaque_metadata: Dict[str, Tuple] = {}

    def process_constant(self, hex_value: str, is_arithmetic: bool = False,
                        meta: Optional[Dict] = None, library_type: str = "unknown") -> Tokens:
        """
        Process a constant value and return the appropriate token.

        Args:
            hex_value: Hex string representation of the constant (e.g., "0x42")
            is_arithmetic: Whether this constant is used in arithmetic operations
            meta: Optional metadata for opaque constants
            library_type: Type of library for opaque constants

        Returns:
            TokensRepl object representing the constant
        """
        # Remove '0x' prefix if present
        clean_hex = hex_value[2:] if hex_value.startswith('0x') else hex_value

        # Convert to integer for range checking
        try:
            value = int(clean_hex, 16)
        except ValueError:
            raise ValueError(f"Invalid hex value: {hex_value}")

        # Check if it's a small constant (0x00 to 0xFF)
        if is_arithmetic or 0x00 <= value <= 0xFF or hex_value in self.constant_dict:
            return self.vocab_manager.Valued_Const(value)
        else:
            return self._create_opaque_const(hex_value, meta, library_type)


    def _create_opaque_const(self, hex_value: str, meta: Optional[Dict] = None,
                           library_type: str = "unknown") -> Tokens:
        """Create an opaque constant token"""
        if hex_value not in self.opaque_const_tokens:
            # Get or create opaque ID
            opaque_id = self.resolver.get_opaque_id(hex_value)
            token = self.vocab_manager.Opaque_Const(opaque_id)
            self.opaque_const_tokens[hex_value] = token
            self.opaque_const_usage[hex_value] = 1

            # Store metadata if provided
            if meta is not None:
                self.opaque_metadata[hex_value] = (
                    hex(meta["start_addr"]),
                    hex(meta["end_addr"]),
                    meta["name"],
                    meta["type"],
                    library_type
                )
        else:
            self.opaque_const_usage[hex_value] += 1

        return self.opaque_const_tokens[hex_value]

    def get_sorted_opaque_constants(self) -> List[Tuple[str, Tokens, int]]:
        """Get opaque constants sorted by usage count (descending)"""
        return sorted(
            [(hex_val, token, self.opaque_const_usage[hex_val])
             for hex_val, token in self.opaque_const_tokens.items()],
            key=lambda x: x[2], reverse=True
        )

    def create_opaque_mapping(self) -> Dict[BlockToken, Tokens]:
        """
        Create mapping from old opaque tokens to new tokens based on sorted usage.
        This is used for reassigning IDs after sorting by usage.
        """
        sorted_opaques = self.get_sorted_opaque_constants()
        mapping = {}

        old_token: OpaqueConstToken
        # Create new tokens with sequential IDs based on usage ranking
        for new_id, (hex_val, old_token, usage_count) in enumerate(sorted_opaques):
            if new_id != old_token.id:
                new_token = self.vocab_manager.Opaque_Const(new_id)
                mapping[old_token] = new_token

        return mapping

    def get_usage_stats(self) -> Dict[str, Dict[str, int]]:
        """Get usage statistics for all constants"""
        return {
            "value_constants": self.value_constant_usage.copy(),
            "opaque_constants": self.opaque_const_usage.copy()
        }

    def get_metadata(self) -> Dict[str, Tuple]:
        """Get metadata for opaque constants"""
        return self.opaque_metadata.copy()

    def reorder_metadata_for_mapping(self, opaque_mapping: Dict[Tokens, Tokens]) -> None:
        """
        Reorder metadata to match the new token ordering after opaque mapping.

        Args:
            opaque_mapping: Dictionary mapping old opaque tokens to new sorted tokens
        """
        if not opaque_mapping:
            return

        # Create a reverse mapping from old tokens to hex values
        token_to_hex = {}
        for hex_val, token in self.opaque_const_tokens.items():
            token_to_hex[token] = hex_val

        # Create new metadata dict with reordered entries
        new_metadata = {}

        # Process each mapping
        for old_token, new_token in opaque_mapping.items():
            if old_token in token_to_hex:
                hex_val = token_to_hex[old_token]
                if hex_val in self.opaque_metadata:
                    # The metadata stays with the hex value, but we need to ensure
                    # it's accessible via the new token's ID
                    new_metadata[hex_val] = self.opaque_metadata[hex_val]

        # Update the metadata dict
        for hex_val, metadata in new_metadata.items():
            self.opaque_metadata[hex_val] = metadata

