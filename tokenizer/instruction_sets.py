"""
Instruction sets classification for assembly instruction categorization.
"""


class InstructionSets:
    """
    Container class for different categories of assembly instructions.
    Provides easy access to instruction sets loaded from data store.
    """

    def __init__(self, data_store_path: str = "tokenizer/data_store.json"):
        """
        Initialize instruction sets from data store.

        Args:
            data_store_path: Path to the JSON data store file
        """
        import json

        with open(data_store_path) as f:
            data = json.load(f)

        self.arithmetic: set[str] = set(data["arithmetic_instructions"])
        self.addressing_control_flow: set[str] = set(data["addressing_control_flow_instructions"])
        self.string: set[str] = set(data["string_instructions"])
        self.bit_manipulation: set[str] = set(data["bit_manipulation_instructions"])
        self.floating_point: set[str] = set(data["floating_point_instructions"])
        self.system: set[str] = set(data["system_instructions"])
        self.prefixes: dict[int, str] = {int(k, 16): v for k, v in data["inv_prefix_tokens"].items()}

    @classmethod
    def from_data_dict(cls, data: dict) -> 'InstructionSets':
        """
        Create InstructionSets from pre-loaded data dictionary.

        Args:
            data: Dictionary containing instruction set data

        Returns:
            InstructionSets instance
        """
        instance = cls.__new__(cls)
        instance.arithmetic = set(data["arithmetic_instructions"])
        instance.addressing_control_flow = set(data["addressing_control_flow_instructions"])
        instance.string = set(data["string_instructions"])
        instance.bit_manipulation = set(data["bit_manipulation_instructions"])
        instance.floating_point = set(data["floating_point_instructions"])
        instance.system = set(data["system_instructions"])
        instance.prefixes =  {int(k, 16): v for k, v in data["inv_prefix_tokens"].items()}
        return instance

    def __repr__(self) -> str:
        return (f"InstructionSets(arithmetic={len(self.arithmetic)}, "
                f"addressing_control_flow={len(self.addressing_control_flow)}, "
                f"string={len(self.string)}, bit_manipulation={len(self.bit_manipulation)}, "
                f"floating_point={len(self.floating_point)}, system={len(self.system)})")
