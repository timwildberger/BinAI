from enum import Enum, auto
from typing import Iterator, Any, Optional, List
import traceback

from tokenizer.architecture import PlatformInstructionTypes
from tokenizer.tokens import TokenType, MemoryOperandSymbol, TokenRaw


DEBUG_PATTERN = True  # Set to True to enable debug prints

class RepeatType(Enum):
    MAYBE = auto()
    ONE = auto()
    MULTIPLE = auto()


class TokenBuffer:
    def __init__(self, token_iter: Iterator[Any]):
        self._iter = token_iter
        self._buffer: List[Any] = []
        self._resolved: List[bool] = []

    def get(self, idx: int) -> Any:
        while len(self._buffer) <= idx:
            try:
                self._buffer.append(next(self._iter))
                self._resolved.append(False)
            except StopIteration:
                return None
        return self._buffer[idx]

    def set(self, idx: int, value: Any):
        self._buffer[idx] = value
        self._resolved[idx] = True

    def resolved(self, idx: int) -> bool:
        return idx < len(self._resolved) and self._resolved[idx]

    def length(self) -> int:
        while True:
            try:
                self._buffer.append(next(self._iter))
                self._resolved.append(False)
            except StopIteration:
                break
        return len(self._buffer)

    def slice(self, start: int, end: int) -> List[Any]:
        for i in range(end):
            self.get(i)
        return self._buffer[start:end]

    def checkpoint(self):
        # Save current buffer state for backtracking
        return (list(self._buffer), list(self._resolved))

    def restore(self, checkpoint):
        buffer, resolved = checkpoint
        self._buffer = buffer[:]
        self._resolved = resolved[:]

class PatternElem:
    def __init__(self):
        self._last_error: Optional[str] = None
        self._last_trace: Optional[List[str]] = None
        self._last_python_trace: Optional[str] = None

    def match_throw(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any], trace=None) -> int:
        raise NotImplementedError

    def match(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any], trace=None) -> Optional[int]:
        self._last_error = None
        self._last_trace = None
        self._last_python_trace = None
        if trace is None:
            trace = []
        try:
            res = self.match_throw(buf, start, vocab_manager, trace)
            if DEBUG_PATTERN:
                print(f"[ACCEPT] {self.__class__.__name__} at pos {start} -> {res}")
            return res
        except Exception as e:
            if DEBUG_PATTERN:
                print(f"[REJECT] {self.__class__.__name__} at pos {start}: {e}")
            self._last_error = str(e)
            self._last_trace = trace + [f"Exception: {str(e)}"]
            self._last_python_trace = traceback.format_exc()
            return None

    def get_error(self) -> Optional[str]:
        return self._last_error

    def get_error_trace(self) -> Optional[str]:
        # Return the stack trace as a string
        if self._last_trace is None:
            return None
        return "\n".join(self._last_trace)

    def get_python_trace(self) -> Optional[str]:
        return self._last_python_trace

    def __repr__(self):
        return f"{self.__class__.__name__}({self.__dict__})"


class One(PatternElem):
    def __init__(self, pat):
        super().__init__()
        self.pat = pat

    def match_throw(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any], trace=None) -> int:
        if trace is None:
            trace = []
        trace = trace + [f"One({repr(self.pat)}) at pos {start}"]
        tok = buf.get(start)
        if tok is None:
            raise RuntimeError(f"Expected token at position {start}, got None")
        if not buf.resolved(start):
            tok2 = TokenPattern._resolve_token_or_error(tok, self.pat, vocab_manager)
            if tok2 is not tok:
                buf.set(start, tok2)
            tok = tok2

        # Helper to resolve enum values to names for error reporting
        def enum_name(val, enum_cls):
            try:
                return enum_cls(val).name
            except Exception:
                return str(val)

        token_type_val = getattr(tok, 'token_type', None)
        symbol_val = getattr(tok, 'symbol', None)
        platform_type_val = getattr(tok, 'platform_instruction_type', None)
        platform_type_str = enum_name(platform_type_val, PlatformInstructionTypes) if platform_type_val is not None else None

        pat_str = self.pat
        if isinstance(self.pat, PlatformInstructionTypes):
            pat_str = f"{self.pat.name} ({self.pat.value})"
        elif isinstance(self.pat, TokenType):
            pat_str = f"{self.pat.name} ({self.pat.value})"
        elif isinstance(self.pat, MemoryOperandSymbol):
            pat_str = f"{self.pat.name}"

        if TokenPattern._token_matches(tok, self.pat):
            if DEBUG_PATTERN:
                print(f"[ACCEPT] One({repr(self.pat)}) at pos {start}")
            return 1
        if DEBUG_PATTERN:
            print(f"[REJECT] One({repr(self.pat)}) at pos {start}")
        raise RuntimeError(
            f"Token at position {start} did not match pattern {pat_str}. "
            f"Actual token_type: {enum_name(token_type_val, TokenType)}, "
            f"symbol: {getattr(symbol_val, 'name', symbol_val)}, "
            f"platform_instruction_type: {platform_type_str}"
        )

    def __repr__(self):
        return f"One({repr(self.pat)})"


class WithValue(PatternElem):
    def __init__(self, token_type, value):
        super().__init__()
        self.token_type = token_type
        self.value = value

    def match_throw(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any], trace=None) -> int:
        if trace is None:
            trace = []
        trace = trace + [f"WithValue({self.token_type}, {self.value}) at pos {start}"]
        tok = buf.get(start)
        if tok is None:
            raise RuntimeError(f"Expected token at position {start}, got None")
        token_type_val = getattr(tok, 'token_type', None)
        token_type_str = TokenType(token_type_val).name if token_type_val in TokenType._value2member_map_ else str(token_type_val)
        if not (hasattr(tok, "token_type") and tok.token_type == self.token_type):
            raise RuntimeError(
                f"Token at position {start} does not have expected token_type {self.token_type.name}, "
                f"got {token_type_str}"
            )
        if hasattr(tok, "resolve") and not buf.resolved(start):
            tok2 = tok.resolve(vocab_manager)
            buf.set(start, tok2)
            tok = tok2
        if self.token_type == TokenType.VALUED_CONST or self.token_type == TokenType.OPAQUE_CONST:
            if hasattr(tok, "value"):
                if tok.value == self.value:
                    if DEBUG_PATTERN:
                        print(f"[ACCEPT] WithValue({self.token_type}, {self.value}) at pos {start}")
                    return 1
                else:
                    if DEBUG_PATTERN:
                        print(f"[REJECT] WithValue({self.token_type}, {self.value}) at pos {start}")
                    raise RuntimeError(
                        f"Token at position {start} has value {tok.value}, expected {self.value}. Token: {tok}"
                    )
            else:
                if DEBUG_PATTERN:
                    print(f"[REJECT] WithValue({self.token_type}, {self.value}) at pos {start}")
                raise RuntimeError(
                    f"Token at position {start} does not have a 'value' attribute. Token: {tok}"
                )
        elif self.token_type == TokenType.BLOCK:
            if hasattr(tok, "id"):
                if tok.id == self.value:
                    if DEBUG_PATTERN:
                        print(f"[ACCEPT] WithValue({self.token_type}, {self.value}) at pos {start}")
                    return 1
                else:
                    if DEBUG_PATTERN:
                        print(f"[REJECT] WithValue({self.token_type}, {self.value}) at pos {start}")
                    raise RuntimeError(
                        f"Token at position {start} has id {tok.id}, expected {self.value}. Token: {tok}"
                    )
            else:
                if DEBUG_PATTERN:
                    print(f"[REJECT] WithValue({self.token_type}, {self.value}) at pos {start}")
                raise RuntimeError(
                    f"Token at position {start} does not have an 'id' attribute. Token: {tok}"
                )
        elif self.token_type == TokenType.PLATFORM:
            if hasattr(tok, "token"):
                if tok.token == self.value:
                    if DEBUG_PATTERN:
                        print(f"[ACCEPT] WithValue({self.token_type}, {self.value}) at pos {start}")
                    return 1
                else:
                    if DEBUG_PATTERN:
                        print(f"[REJECT] WithValue({self.token_type}, {self.value}) at pos {start}")
                    raise RuntimeError(
                        f"Token at position {start} has token '{tok.token}', expected '{self.value}'. Token: {tok}"
                    )
            else:
                if DEBUG_PATTERN:
                    print(f"[REJECT] WithValue({self.token_type}, {self.value}) at pos {start}")
                raise RuntimeError(
                    f"Token at position {start} does not have a 'token' attribute. Token: {tok}"
                )
        if DEBUG_PATTERN:
            print(f"[REJECT] WithValue({self.token_type}, {self.value}) at pos {start}")
        raise RuntimeError(
            f"Token at position {start} did not match value {self.value}. Token: {tok}"
        )

    def __repr__(self):
        return f"WithValue(token_type={self.token_type}, value={self.value})"


class MaybeOne(PatternElem):
    def __init__(self, pat):
        super().__init__()
        self.pat = pat

    def match_throw(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any], trace=None) -> int:
        if trace is None:
            trace = []
        trace = trace + [f"MaybeOne({repr(self.pat)}) at pos {start}"]
        checkpoint = buf.checkpoint()
        try:
            res = self.pat.match_throw(buf, start, vocab_manager, trace)
            if DEBUG_PATTERN:
                print(f"[ACCEPT] MaybeOne({repr(self.pat)}) at pos {start} -> {res}")
            return res
        except Exception as e:
            buf.restore(checkpoint)
            if DEBUG_PATTERN:
                print(f"[REJECT] MaybeOne({repr(self.pat)}) at pos {start}: {e}")
            self._last_error = f"MaybeOne failed at position {start}: {str(e)}"
            self._last_trace = trace + [f"Exception: {str(e)}"]
            self._last_python_trace = traceback.format_exc()
            return 0

    def __repr__(self):
        return f"MaybeOne({repr(self.pat)})"


class ZeroOrMore(PatternElem):
    def __init__(self, pat):
        super().__init__()
        self.pat = pat

    def match_throw(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any], trace=None) -> int:
        if trace is None:
            trace = []
        trace = trace + [f"ZeroOrMore({repr(self.pat)}) at pos {start}"]
        idx = start
        errors = []
        backtrack_traces = []
        while True:
            try:
                res = self.pat.match_throw(buf, idx, vocab_manager, trace + [f"ZeroOrMore iteration at {idx}"])
                if res > 0:
                    if DEBUG_PATTERN:
                        print(f"[ACCEPT] ZeroOrMore({repr(self.pat)}) at pos {idx} -> {res}")
                    idx += res
                else:
                    if DEBUG_PATTERN:
                        print(f"[REJECT] ZeroOrMore({repr(self.pat)}) at pos {idx} (zero match)")
                    break
            except Exception as e:
                if DEBUG_PATTERN:
                    print(f"[REJECT] ZeroOrMore({repr(self.pat)}) at pos {idx}: {e}")
                errors.append(f"ZeroOrMore failed at position {idx}: {str(e)}")
                backtrack_traces.append(traceback.format_exc())
                break
        if errors:
            self._last_error = "; ".join(errors)
            self._last_trace = trace + errors + backtrack_traces
            self._last_python_trace = "\n".join(backtrack_traces)
        return idx - start

    def __repr__(self):
        return f"ZeroOrMore({repr(self.pat)})"


class OneOrMore(PatternElem):
    def __init__(self, pat):
        super().__init__()
        self.pat = pat

    def match_throw(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any], trace=None) -> int:
        if trace is None:
            trace = []
        trace = trace + [f"OneOrMore({repr(self.pat)}) at pos {start}"]
        idx = start
        errors = []
        backtrack_traces = []
        try:
            first = self.pat.match_throw(buf, idx, vocab_manager, trace + [f"OneOrMore first at {idx}"])
            if DEBUG_PATTERN:
                print(f"[ACCEPT] OneOrMore({repr(self.pat)}) first at pos {idx} -> {first}")
        except Exception as e:
            if DEBUG_PATTERN:
                print(f"[REJECT] OneOrMore({repr(self.pat)}) first at pos {idx}: {e}")
            errors.append(f"OneOrMore expected at least one match at position {start}: {str(e)}")
            backtrack_traces.append(traceback.format_exc())
            raise RuntimeError(errors[-1])
        if first == 0:
            if DEBUG_PATTERN:
                print(f"[REJECT] OneOrMore({repr(self.pat)}) first at pos {idx} (zero match)")
            raise RuntimeError(f"OneOrMore expected at least one match at position {start}, got zero")
        idx += first
        while True:
            try:
                res = self.pat.match_throw(buf, idx, vocab_manager, trace + [f"OneOrMore iteration at {idx}"])
                if res > 0:
                    if DEBUG_PATTERN:
                        print(f"[ACCEPT] OneOrMore({repr(self.pat)}) iteration at pos {idx} -> {res}")
                    idx += res
                else:
                    if DEBUG_PATTERN:
                        print(f"[REJECT] OneOrMore({repr(self.pat)}) iteration at pos {idx} (zero match)")
                    break
            except Exception as e:
                if DEBUG_PATTERN:
                    print(f"[REJECT] OneOrMore({repr(self.pat)}) iteration at pos {idx}: {e}")
                errors.append(f"OneOrMore failed at position {idx}: {str(e)}")
                backtrack_traces.append(traceback.format_exc())
                break
        if errors:
            self._last_error = "; ".join(errors)
            self._last_trace = trace + errors + backtrack_traces
            self._last_python_trace = "\n".join(backtrack_traces)
        return idx - start

    def __repr__(self):
        return f"OneOrMore({repr(self.pat)})"


class Alternatives(PatternElem):
    def __init__(self, alternatives: List[PatternElem]):
        super().__init__()
        self.alternatives = alternatives

    def match_throw(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any], trace=None) -> int:
        if trace is None:
            trace = []
        trace = trace + [f"Alternatives({repr(self.alternatives)}) at pos {start}"]
        errors = []
        python_traces = []
        for alt in self.alternatives:
            checkpoint = buf.checkpoint()
            try:
                res = alt.match_throw(buf, start, vocab_manager, trace + [f"Alternatives branch {repr(alt)}"])
                if DEBUG_PATTERN:
                    print(f"[ACCEPT] Alternatives({repr(alt)}) at pos {start} -> {res}")
                if res > 0:
                    return res
                else:
                    # Restore buffer if zero tokens were matched
                    buf.restore(checkpoint)
                    if DEBUG_PATTERN:
                        print(f"[REJECT] Alternatives({repr(alt)}) at pos {start}: matched zero tokens")
                    errors.append(f"Alternative {repr(alt)} matched zero tokens at position {start}")
                    python_traces.append(traceback.format_exc())
            except Exception as e:
                buf.restore(checkpoint)
                if DEBUG_PATTERN:
                    print(f"[REJECT] Alternatives({repr(alt)}) at pos {start}: {e}")
                errors.append(str(e))
                python_traces.append(traceback.format_exc())
        self._last_error = f"None of the alternatives matched at position {start}: {errors}"
        self._last_trace = trace + errors + python_traces
        self._last_python_trace = "\n".join(python_traces)
        raise RuntimeError(self._last_error)

    def __repr__(self):
        return f"Alternatives({repr(self.alternatives)})"


class Sequence(PatternElem):
    def __init__(self, sequence: List['PatternElem']):
        super().__init__()
        self.sequence = sequence

    def match_throw(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any], trace=None) -> int:
        if trace is None:
            trace = []
        trace = trace + [f"Sequence({repr(self.sequence)}) at pos {start}"]
        idx = start
        for elem in self.sequence:
            checkpoint = buf.checkpoint()
            try:
                res = elem.match_throw(buf, idx, vocab_manager, trace + [f"Sequence element {repr(elem)}"])
                if DEBUG_PATTERN:
                    print(f"[ACCEPT] Sequence element {repr(elem)} at pos {idx} -> {res}")
                idx += res
            except Exception as e:
                buf.restore(checkpoint)
                if DEBUG_PATTERN:
                    print(f"[REJECT] Sequence element {repr(elem)} at pos {idx}: {e}")
                if hasattr(elem, '_last_trace') and elem._last_trace:
                    combined_trace = trace + [f"Sequence failed at position {idx} for element {repr(elem)}: {str(e)}"] + elem._last_trace
                else:
                    combined_trace = trace + [f"Sequence failed at position {idx} for element {repr(elem)}: {str(e)}"]
                self._last_error = f"Sequence failed at position {idx} for element {repr(elem)}: {str(e)}"
                self._last_trace = combined_trace
                self._last_python_trace = traceback.format_exc()
                raise
        return idx - start

    def __repr__(self):
        return f"Sequence({repr(self.sequence)})"


class TokenPattern(PatternElem):
    def __init__(self, *args):
        super().__init__()
        self.pattern = self._parse_args(args)
        if isinstance(self.pattern, list) and len(self.pattern) == 1:
            self.pattern = self.pattern[0]

    @staticmethod
    def _is_resolvable_type(pat):
        return isinstance(pat, (MemoryOperandSymbol, PlatformInstructionTypes))

    @staticmethod
    def _token_matches(tok, pat):
        # If pattern is PlatformInstructionTypes, match against platform_instruction_type
        if isinstance(pat, PlatformInstructionTypes):
            return hasattr(tok, "platform_instruction_type") and tok.platform_instruction_type == pat
        # If pattern is TokenType, match against token_type
        if isinstance(pat, TokenType):
            return hasattr(tok, "token_type") and tok.token_type == pat
        # If pattern is MemoryOperandSymbol, match against symbol
        if isinstance(pat, MemoryOperandSymbol):
            return hasattr(tok, "symbol") and tok.symbol == pat
        # Fallback to previous logic
        return (
            hasattr(tok, "token_type") and tok.token_type == pat or
            hasattr(tok, "symbol") and tok.symbol == pat or
            hasattr(tok, "platform_instruction_type") and tok.platform_instruction_type == pat
        )

    @staticmethod
    def _is_raw_token(tok):
        return isinstance(tok, TokenRaw)

    @staticmethod
    def _resolve_token_or_error(tok, pat, vocab_manager):
        if vocab_manager is not None and TokenPattern._is_resolvable_type(pat):
            if TokenPattern._is_raw_token(tok):
                if vocab_manager is None:
                    raise RuntimeError(f"Token {tok} must be resolved but does not support resolve()")
                return tok.resolve(vocab_manager)
            else:
                return tok
        return tok

    def _parse_args(self, args):
        pattern = []
        i = 0
        while i < len(args):
            arg = args[i]
            # Handle RepeatType as a prefix to the pattern
            if isinstance(arg, RepeatType):
                # Only allow RepeatType followed by a pattern (not another RepeatType)
                if i + 1 >= len(args):
                    raise ValueError("RepeatType must be followed by a pattern")
                next_arg = args[i + 1]
                # If next_arg is a tuple/list, parse it as a pattern
                # --- FIX: If next_arg is a tuple of length 1, unwrap it ---
                if isinstance(next_arg, tuple) and len(next_arg) == 1:
                    pat = self._parse_args([next_arg[0]])
                elif isinstance(next_arg, (tuple, list)):
                    pat = self._parse_args([next_arg])
                else:
                    pat = self._parse_args([next_arg])
                if arg == RepeatType.ONE:
                    pattern.append(One(pat if not isinstance(pat, list) else pat[0]))
                elif arg == RepeatType.MAYBE:
                    pattern.append(MaybeOne(pat if not isinstance(pat, list) else pat[0]))
                elif arg == RepeatType.MULTIPLE:
                    pattern.append(OneOrMore(pat if not isinstance(pat, list) else pat[0]))
                i += 2
                continue
            elif isinstance(arg, tuple):
                # --- FIX: Only wrap in Alternatives if tuple has >1 element ---
                if len(arg) == 1:
                    parsed = self._parse_args([arg[0]])
                    if isinstance(parsed, list):
                        pattern.extend(parsed)
                    else:
                        pattern.append(parsed)
                else:
                    alt_elems = []
                    j = 0
                    while j < len(arg):
                        a = arg[j]
                        # If a is RepeatType, handle as prefix
                        if isinstance(a, RepeatType):
                            if j + 1 >= len(arg):
                                raise ValueError("RepeatType in tuple must be followed by a pattern")
                            next_a = arg[j + 1]
                            # --- FIX: If next_a is tuple of length 1, unwrap ---
                            if isinstance(next_a, tuple) and len(next_a) == 1:
                                pat = self._parse_args([next_a[0]])
                            elif isinstance(next_a, (tuple, list)):
                                pat = self._parse_args([next_a])
                            else:
                                pat = self._parse_args([next_a])
                            if a == RepeatType.ONE:
                                alt_elems.append(One(pat if not isinstance(pat, list) else pat[0]))
                            elif a == RepeatType.MAYBE:
                                alt_elems.append(MaybeOne(pat if not isinstance(pat, list) else pat[0]))
                            elif a == RepeatType.MULTIPLE:
                                alt_elems.append(OneOrMore(pat if not isinstance(pat, list) else pat[0]))
                            j += 2
                            continue
                        else:
                            parsed = self._parse_args([a])
                            if isinstance(parsed, list):
                                alt_elems.extend(parsed)
                            else:
                                alt_elems.append(parsed)
                            j += 1
                    pattern.append(Alternatives(alt_elems))
            elif isinstance(arg, list):
                # Flatten sequence
                seq_elems = []
                for a in arg:
                    parsed = self._parse_args([a])
                    if isinstance(parsed, list):
                        seq_elems.extend(parsed)
                    else:
                        seq_elems.append(parsed)
                pattern.append(Sequence(seq_elems))
            elif self._is_resolvable_type(arg):
                pattern.append(One(arg))
            elif (
                isinstance(arg, tuple)
                and len(arg) == 2
                and isinstance(arg[0], TokenType)
                and (
                    isinstance(arg[1], (int, str))
                )
            ):
                pattern.append(WithValue(arg[0], arg[1]))
            else:
                pattern.append(One(arg))
            i += 1
        # If only one element, return it directly
        if len(pattern) == 1:
            return pattern[0]
        return pattern

    def match(self, token_iter: Iterator[Any], vocab_manager: Optional[Any] = None) -> bool:
        buf = TokenBuffer(token_iter)
        self._last_error = None
        self._last_trace = None
        self._last_python_trace = None
        if isinstance(self.pattern, PatternElem):
            res = self.pattern.match(buf, 0, vocab_manager)
            self._last_error = self.pattern.get_error()
            self._last_trace = self.pattern.get_error_trace()
            self._last_python_trace = self.pattern.get_python_trace()
        else:
            seq = Sequence(self.pattern)
            res = seq.match(buf, 0, vocab_manager)
            self._last_error = seq.get_error()
            self._last_trace = seq.get_error_trace()
            self._last_python_trace = seq.get_python_trace()
        if res is not None and res == buf.length():
            self._last_error = None
            self._last_trace = None
            self._last_python_trace = None
            return True
        else:
            return False

    def get_error(self) -> Optional[str]:
        return self._last_error

    def get_error_trace(self) -> Optional[str]:
        return self._last_trace

    def get_python_trace(self) -> Optional[str]:
        return self._last_python_trace
