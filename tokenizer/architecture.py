from abc import ABC, abstractmethod
from enum import Enum


class PlatformInstructionTypes(Enum):
    AGNOSTIC = -1
    ARITHMETIC = 0
    PREFIXES = 1
    POINTER_LENGTHS = 2
    MEMORY_ACCESS_MODE = 3
    CONTROL_FLOW = 4
    STRINGS = 5
    FLOARING_POINT = 6
    BIT_MANIPULATION = 7
    SYSTEM = 8
    NOP = 9
    KERNEL_INTERACTION = 10
    LOCKING_ATOMIC = 11

    OTHER = 127

class X86:
    architecture_str = "x86"
    instruction_types_enum = PlatformInstructionTypes

    def __init__(self, instruction_types_class):
        self.instruction_types_class = instruction_types_class
