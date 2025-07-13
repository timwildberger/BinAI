def _create(globals):
    from typing import List, Union

    from tokenizer.patterns.engine import (PatternElem, Alternatives, camelcase, Sequence, RepeatType, TokenTypeElem,
                                           PlatformInstructionTypesElem, MemoryOperandSymbolElem, MaybeElem, MultiElem,
                                           LookaheadElem)

    from tokenizer.architecture import PlatformInstructionTypes
    from tokenizer.tokens import TokenType, MemoryOperandSymbol

    TokenPatternType = Union['Pattern', 'PartialParseResult', List['TokenPatternType']]

    def parse_list(list_: List[TokenPatternType]) -> Union['PartialParseResult', NotImplemented]:
        result = []
        for x in list_:
            if isinstance(x, PartialParseResult):
                result.append(x.finalize())
            elif isinstance(x, Pattern):
                result.append(x.to_pattern_elem())
            elif isinstance(x, list):
                nested = parse_list(x)
                if nested == NotImplemented:
                    return NotImplemented
                result.append(nested.finalize())
            else:
                return NotImplemented

        return PartialParseResult([Sequence(result)], [])

    # --- PartialParseResult class ---
    from abc import ABC, abstractmethod
    class PatternParseBase(ABC):

        @abstractmethod
        def __add__(self, other):
            """
            Adds another pattern or prefix to this result.
            """
            pass

        @abstractmethod
        def __or__(self, other):
            """
            Adds another pattern or prefix to this result.
            """
            pass



    class PartialParseResult(PatternParseBase):
        def __init__(self, parsed, end):
            self.parsed: List[PatternElem] = parsed  # list of PatternElem (fully parsed)
            self.end: List[Prefix | Pattern] = end  # list of Prefix/Pattern (not yet parsed)
            self.building_alternative = False

        def __add__(self, other):
            if isinstance(other, List):
                other = parse_list(other)

            if other == NotImplemented:
                return NotImplemented

            if isinstance(other, PartialParseResult):
                if self.building_alternative:
                    return NotImplemented
                elif other.building_alternative:
                    self._finish_section(other.finalize())
                else:
                    if len(other.parsed) > 0:
                        self._finish_section(other.parsed[0])
                        self.parsed.extend(other.parsed[1:])
                    for elem in other.end:
                        self + elem

                return self

            if not self.end:
                if isinstance(other, (Prefix, Pattern)):
                    self.end.append(other)
                    return self
                else:
                    return NotImplemented
            last = self.end.pop()
            # If last is Prefix, delegate to its __add__
            if isinstance(last, Pattern) and isinstance(other, (Prefix, Pattern, PartialParseResult)):
                return NotImplemented  # should use comma instead of plus
            elif isinstance(last, (Prefix | Pattern)):
                result = last.__add__(other)
                if isinstance(result, PartialParseResult):
                    if result.parsed and result.end:
                        raise ValueError("Result must either be fully parsed or fully unparsed.")
                    if result.parsed:
                        # Instead of just extending, traverse end backwards and construct pattern elements
                        assert len(result.parsed) == 1, "Parsed result must contain exactly one element."
                        self._finish_section(result.parsed[0])
                    else:
                        self.end.extend(result.end)
                elif isinstance(result, Prefix):
                    return self + result
                elif isinstance(result, PatternElem):
                    self._finish_section(result)
                else:
                    self.end.append(result)
                return self
            # Otherwise, add to end
            elif isinstance(other, PartialParseResult):
                return PartialParseResult(self.parsed + other.parsed, self.end + other.end)
            else:
                return NotImplemented

        def _finish_section(self, constructed):
            for prefix in reversed(self.end):
                if isinstance(prefix, Prefix):
                    constructed = prefix.to_pattern_elem(constructed)
                else:
                    raise ValueError("must be prefixed by prefixes.")
            self.parsed.append(constructed)
            self.end = []

        def finalize(self) -> PatternElem:
            if self.end:
                assert isinstance(self.end[-1], Pattern), "Last element must be a Pattern when finalizing."
                self._finish_section(self.end.pop().to_pattern_elem())

            if self.building_alternative:
                return Alternatives(self.parsed)
            else:
                assert len(self.parsed) == 1, "Single parsed element cannot be two"
                return self.parsed[0]

        def __or__(self, other):
            if self.end:
                assert isinstance(self.end[-1], Pattern), "Last element must be a Pattern when finishing section."
                self._finish_section(self.end.pop().to_pattern_elem())
            self.building_alternative = True

            if isinstance(other, PartialParseResult):

                assert other.building_alternative or len(
                    other.parsed) <= 1, "PartialParseResult must be empty/one or building alternative."

                if not other.building_alternative and len(other.parsed) == 1:
                    self.parsed.append(other.parsed[0])
                else:
                    self.parsed.extend(other.parsed)
                self.end = other.end
            elif isinstance(other, (Prefix, Pattern)):
                self.end = [other]
            else:
                return NotImplemented

            return self

        def __str__(self):
            symbol = " | " if self.building_alternative else ", "
            inner = f"({symbol.join([str(x) for x in self.parsed])})"
            if not self.end:
                return inner
            return f"({inner}, unparsed={self.end})"

        def __repr__(self):
            if not self.end:
                return str(self)
            symbol = " | " if self.building_alternative else ", "
            return f"PartialParseResult(parsed={symbol.join([repr(x) for x in self.parsed])}, unparsed={repr(self.end)})"

    class Prefix(PatternParseBase):
        def __init__(self, value):
            self.value = value

        def to_pattern_elem(self, elem: PatternElem) -> PatternElem:
            # Construct Maybe, Multi, Lookahead pattern elements based on prefix type
            if self.value.name == "MAYBE":
                return MaybeElem(elem)
            elif self.value.name == "MULTI":
                return MultiElem(elem)
            elif self.value.name == "LOOKAHEAD":
                return LookaheadElem(elem)
            else:
                raise ValueError(f"Unknown prefix type: {self.value}")

        def __add__(self, other):
            # previous is PartialParseResult
            # A) If Prefix + Prefix, apply rules:
            if isinstance(other, Prefix):
                def combine(self, other):
                    match (self, other):
                        case (RepeatType.MAYBE, RepeatType.MAYBE):
                            return RepeatType.MAYBE
                        case (RepeatType.MULTI, RepeatType.MULTI) | (RepeatType.MULTI, RepeatType.MAYBE):
                            return RepeatType.MULTI
                        case (RepeatType.LOOKAHEAD, RepeatType.MULTI) | (RepeatType.MULTI, RepeatType.LOOKAHEAD) | ( \
                            RepeatType.LOOKAHEAD, RepeatType.LOOKAHEAD):
                            return RepeatType.LOOKAHEAD
                        case (RepeatType.LOOKAHEAD, RepeatType.MAYBE) | (RepeatType.MAYBE, RepeatType.LOOKAHEAD):
                            return []
                        case (RepeatType.MAYBE, RepeatType.MULTI):
                            return [Prefix(RepeatType.MAYBE), Prefix(RepeatType.MULTI)]
                        case _:
                            return [self, other]

                # Rules for combining Prefixes
                result = combine(self.value, other.value)
                if isinstance(result, list):
                    return PartialParseResult([], result)
                else:
                    return Prefix(result)

            if isinstance(other, Pattern):
                return PartialParseResult([], [self, other])
            if isinstance(other, List):
                return self + parse_list(other)
            elif isinstance(other, PartialParseResult):
                return PartialParseResult([], [self]) + other
            else:
                return NotImplemented

        def __or__(self, other):
            return NotImplemented

        def __str__(self):
            return f"Prefix({self.value})"

        def __repr__(self):
            return self.__str__()

    class Pattern(PatternParseBase):
        def __init__(self, cls, value):
            self.value = value
            self.cls = cls  # Class of PatternElem to create

        def to_pattern_elem(self) -> PatternElem:
            return self.cls(self.value)

        def __add__(self, other):
            if isinstance(other, int) and isinstance(self.value, TokenType):
                result = self.to_pattern_elem().with_value(other)
                if result is not None:
                    return PartialParseResult([result], [])

            return NotImplemented

        def __or__(self, other):
            if isinstance(other, (Pattern | Prefix | PartialParseResult)):
                result = PartialParseResult([self.to_pattern_elem()], [])
                return result | other
            elif isinstance(other, List):
                return self | parse_list(other)
            else:
                return NotImplemented

        def __str__(self):
            return f"Pattern({self.cls._format_enum(self.value)})"

        def __repr__(self):
            return self.__str__()

    # --- Reexports for PlatformInstructionTypes, TokenType, MemoryOperandSymbol ---

    # PlatformInstructionTypes
    for member in PlatformInstructionTypes:
        globals[f"Insn{camelcase(member.name)}"] = Pattern(PlatformInstructionTypesElem, member)

    # TokenType
    for member in TokenType:
        globals[camelcase(member.name)] = Pattern(TokenTypeElem, member)

    # MemoryOperandSymbol
    for member in MemoryOperandSymbol:
        globals[f"Mem{camelcase(member.name)}"] = Pattern(MemoryOperandSymbolElem, member)

    # --- Reexports for RepeatType as Prefixes ---
    for member in RepeatType:
        globals[camelcase(member.name)] = Prefix(member)

    globals['PatternParseBase'] = PatternParseBase
    globals['PatternSinglet'] = Pattern
    globals['PatternParseResult'] = PartialParseResult
    globals['listToPatternParseResult'] = parse_list
    globals['TokenPatternType'] = TokenPatternType


_create(globals())
del _create