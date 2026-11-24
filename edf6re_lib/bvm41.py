"""EDF BVM mission-script containers (the format EDF4.1 / EDF5 ship and EDF6's EDF5_OLD_SCRIPT runtime runs).

Container parsing, disassembly support and static checks only; this module carries no game script content.

    parse(data) -> Program, build(prog) -> bytes   the container; parse + build round-trips a BVM byte for byte
    _decode(data, start, end)                      (offset, op, size, operand, type) per instruction (disassembly)
    stack_check(prog, effects=NET6)                where a script's stack does not balance
    type_check(prog, sigs=SIG6), native_calls(...) argument types / literals each native call receives

Format (all little-endian; offsets are file offsets)
  0x00 'BVM '   0x04 0x50 (header size)   0x08 0, 0   0x10 0x01150138   0x14 2
  0x18 global count      0x1C global table (0x50; u32 name offset each)
  0x20 function count    0x24 function table (after the globals; 16 bytes each: code offset from [0x34], name offset,
                         parameter type bytes offset, packed signature: low byte parameter count, upper bytes flags)
  0x28 0x200, 0x2C 0x200 (stacks)
  0x30 code start (after the function table)      0x34 function code base (the initialiser ends here)
  0x38 string pool start (right after the code)   0x3C script name offset ('Mission', 'Before', ...: the file stem)
  0x40 0, 0x44 end of the name rounded up to 4, 0x48 0, 0x4C that rounded up to 16 = file size (padding 0xBA)
  Code: the initialiser (global = constant; ... ; end), then each function: its epilogue (pushl 0; fp+ N; ret) and
  body (fp- N; storel 0; storel <params> ...; ends jumping back to the epilogue), in table order; then one stub per
  function (call <body>; end) that the table points at.
  String pool, unaligned UTF-16LE with a 0 terminator each: the literals (each once, in the order the code first
  pushes them; pushs takes the byte offset from the pool start), then the global names, the function names, all the
  parameter type bytes back to back (01 int, 02 float, 03 string), the script name.
  Instruction: byte op | size << 6 (size 0/1/2/3 = 0/1/2/4 operand bytes; no operand reads as 0), the operand, and for
  the typed ops (TYPED) one type byte. Operands: signed for push / pushla / jumps / call (relative to the opcode),
  unsigned otherwise. Natives are op 0x2C..0x2F (four tables, ids are per table) with the id as operand.
  EDF's compiler sizes operands minimally, except jumps and calls: it starts every operand at 4 bytes (a 0x34 / 0x35
  case jump 2 more), then fixes the instructions front to back; a jump takes 1 byte if, with what follows still at
  the starting sizes, the target is <= 127 bytes ahead (126 for a conditional jump or call), or, backward, >= -122.

Written for this project; MIT license (see LICENSE).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable

MAGIC = b'BVM '
HEADER_SIZE = 0x50
VERSION = 0x01150138
PAD = 0xBA

SIZES = (0, 1, 2, 4)
TYPED = frozenset({0x01, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                   0x31})
SIGNED = frozenset({0x15, 0x18, 0x26, 0x27, 0x28, 0x29, 0x34, 0x35})
OP_STOREI, OP_POP, OP_NEG, OP_AND = 0x01, 0x02, 0x09, 0x1D
OP_PUSHG, OP_PUSH, OP_STOREG, OP_PUSHL, OP_PUSHLA, OP_STOREL, OP_PUSHS = 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A
OP_FPADD, OP_FPSUB, OP_JZ, OP_JMP, OP_CALL, OP_RET, OP_END = 0x1B, 0x1C, 0x26, 0x28, 0x29, 0x2A, 0x30
OP_PUSH1, OP_JNE, OP_STOREIND, OP_NAT0, OP_NAT1 = 0x33, 0x34, 0x36, 0x2C, 0x2D
JUMPS = frozenset({0x26, 0x27, 0x28, 0x34, 0x35})
OP_NATIVE = frozenset({0x2C, 0x2D, 0x2E, 0x2F})
OPERAND = frozenset({0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x2B, 0x37, OP_CALL}) | OP_NATIVE | JUMPS


@dataclass
class Ins:
    """One instruction. v: the operand; for pushs the string, for a jump the index of its target in the same code
    list, for a call the index of the function. n: operand size in bytes (build() lays jumps and calls out itself).
    t: the type byte of a TYPED op."""
    op: int
    v: int | str = 0
    n: int = 0
    t: int | None = None


@dataclass
class Function:
    name: str
    types: bytes
    code: list[Ins]          # epilogue (pushl 0; fp+ N; ret), then the body
    entry: int = 3           # the body's first instruction
    signature_flags: int = 0  # the table's +0x0D..0x0F bytes, preserved even when not understood

    @property
    def results(self) -> int:
        # EDF6's function starters read only the signed byte at table+0x0C for the parameter count
        # (0x10ACB0B/37, 0x10ACC28/64). The shipped 0x100 signatures (_SetupBarrier, CruiseAndRespawn)
        # leave one value below the return address; their callers pop/store it. Other flag values are unproved.
        if len(self.types) >= 0x80:
            raise ValueError(f'BVM: {self.name}: unsupported signed parameter count {len(self.types)}')
        if self.signature_flags not in (0, 0x100):
            raise ValueError(f'BVM: {self.name}: unknown function signature flags {self.signature_flags:#x}')
        return self.signature_flags >> 8


@dataclass
class Program:
    name: str
    globals: list[str]
    init: list[Ins]
    funcs: list[Function] = field(default_factory=list)


def _wstr(data: bytes, off: int) -> str:
    if off < 0 or off + 2 > len(data):
        raise ValueError(f'BVM: string offset {off:#x} outside file')
    for end in range(off, len(data) - 1, 2):
        if data[end:end + 2] == b'\0\0':
            return data[off:end].decode('utf-16le')
    raise ValueError(f'BVM: unterminated string at {off:#x}')


def _decode(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int, int | None]]:
    """(offset, op, size, operand, type) of each instruction in data[start:end]."""
    out = []
    o = start
    while o < end:
        c = data[o]
        op, n = c & 0x3F, SIZES[c >> 6]
        if op > 0x38:
            raise ValueError(f'BVM: bad opcode {c:#x} at {o:#x}')
        if o + 1 + n + (op in TYPED) > end:
            raise ValueError(f'BVM: truncated instruction at {o:#x}')
        v = int.from_bytes(data[o + 1:o + 1 + n], 'little', signed=op in SIGNED) if n else 0
        t = data[o + 1 + n] if op in TYPED else None
        out.append((o, op, n, v, t))
        o += 1 + n + (op in TYPED)
    if o != end:
        raise ValueError(f'BVM: code runs past {end:#x}')
    return out


def parse(data: bytes) -> Program:
    """The script in data (a 4.1 or an EDF5 BVM)."""
    if len(data) < HEADER_SIZE or data[:4] != MAGIC:
        raise ValueError('BVM: not a BVM file')
    h = struct.unpack_from('<20I', data, 0)
    if h[1] != HEADER_SIZE or h[4] != VERSION:
        raise ValueError(f'BVM: unknown version {h[4]:#x}')
    ng, og, nf, of, code0, fbase, pool = h[6], h[7], h[8], h[9], h[12], h[13], h[14]
    if not HEADER_SIZE <= og <= og + 4 * ng <= of <= of + 16 * nf <= code0 <= fbase <= pool <= len(data):
        raise ValueError('BVM: tables or code outside file or out of order')
    gnames = [_wstr(data, struct.unpack_from('<I', data, og + 4 * i)[0]) for i in range(ng)]
    rows = [struct.unpack_from('<4I', data, of + 16 * i) for i in range(nf)]
    ins = _decode(data, code0, pool)
    at = {o: i for i, (o, *_) in enumerate(ins)}
    stubs, bodies = [], []
    for c, _, _, _ in rows:
        s = at.get(fbase + c)
        if s is None:
            raise ValueError(f'BVM: function call stub {fbase + c:#x} is not an instruction')
        o, op, n, v, t = ins[s]
        if op != OP_CALL or s + 1 >= len(ins) or ins[s + 1][1] != OP_END or o + v not in at:
            raise ValueError(f'BVM: no call stub at {o:#x}')
        stubs.append(s)
        bodies.append(at[o + v])
    if stubs and (stubs != list(range(stubs[0], stubs[0] + 2 * nf, 2)) or stubs[-1] + 2 != len(ins)):
        raise ValueError('BVM: the call stubs are not the end of the code')
    if bodies != sorted(bodies) or any(b < 3 for b in bodies):
        raise ValueError('BVM: function bodies out of table order')
    starts = [b - 3 for b in bodies] + [stubs[0] if stubs else len(ins)]
    if fbase not in at and fbase != pool:
        raise ValueError(f'BVM: function code base {fbase:#x} is not an instruction')
    init_end = at.get(fbase, len(ins))
    if nf and starts[0] != init_end:
        raise ValueError('BVM: code between the initialiser and the first function')
    fn_of_body = {b: i for i, b in enumerate(bodies)}

    def convert_code(lo: int, hi: int) -> list[Ins]:
        out = []
        for i in range(lo, hi):
            o, op, n, v, t = ins[i]
            if op in JUMPS:
                j = at.get(o + v)
                if j is None or not lo <= j < hi:
                    raise ValueError(f'BVM: jump at {o:#x} leaves its function')
                out.append(Ins(op, j - lo, n, t))
            elif op == OP_CALL:
                j = at.get(o + v)
                if j not in fn_of_body:
                    raise ValueError(f'BVM: call at {o:#x} is not to a function')
                out.append(Ins(op, fn_of_body[j], n, t))
            elif op == OP_PUSHS:
                out.append(Ins(op, _wstr(data, pool + v), n, t))
            else:
                out.append(Ins(op, v, n, t))
        return out

    prog = Program(_wstr(data, h[15]), gnames, convert_code(0, init_end))
    for i, (c, name, tp, k) in enumerate(rows):
        count = k & 0xFF
        if count and not pool <= tp <= tp + count <= len(data):
            raise ValueError(f'BVM: function {i} parameter types outside string pool')
        code = convert_code(starts[i], starts[i + 1])
        if [x.op for x in code[:3]] != [OP_PUSHL, OP_FPADD, OP_RET]:
            raise ValueError(f'BVM: function {i} has no epilogue')
        prog.funcs.append(Function(_wstr(data, name), data[tp:tp + count], code, signature_flags=k & ~0xFF))
    return prog


def _usize(v: int) -> int:
    return 0 if v == 0 else 1 if v < 0x100 else 2 if v < 0x10000 else 4


def _ssize(v: int) -> int:
    return 0 if v == 0 else 1 if -0x80 <= v < 0x80 else 2 if -0x8000 <= v < 0x8000 else 4


def _layout(seq: list[Ins], tgt: list[int | None]) -> list[int]:
    """Operand sizes of seq, picked as EDF's compiler picks them (see the format notes). tgt: the index in seq of each
    jump's or call's target, None for the other instructions (their size is the one they carry)."""
    start = [1 + (4 if x.op in OPERAND else x.n) + (x.op in TYPED) + (2 if x.op in (0x34, 0x35) else 0) for x in seq]
    ahead = [0]
    for v in start:
        ahead.append(ahead[-1] + v)
    done = [0]
    out = []
    for i, x in enumerate(seq):
        g = tgt[i]
        if g is None:
            n = x.n
        elif g > i:
            d = ahead[g] - ahead[i] + (x.op != OP_JMP)
            n = 1 if d <= 127 else 2 if d <= 32767 else 4
        else:
            d = done[g] - done[i]
            n = 1 if d >= -122 else 2 if d >= -32762 else 4
        out.append(n)
        done.append(done[-1] + 1 + n + (x.op in TYPED))
    return out


def _align(v: int, a: int) -> int:
    return (v + a - 1) // a * a


def _wz(s: str) -> bytes:
    if '\0' in s:
        raise ValueError(f'BVM: string with a NUL: {s!r}')
    return s.encode('utf-16le') + b'\0\0'


def build(prog: Program) -> bytes:
    """The BVM file of prog."""
    nf, ng = len(prog.funcs), len(prog.globals)
    seq: list[Ins] = list(prog.init)      # the whole code: initialiser, functions, call stubs
    tgt: list[int | None] = [None] * len(seq)
    starts = []
    for f in prog.funcs:
        base = len(seq)
        starts.append(base)
        for x in f.code:
            seq.append(x)
            tgt.append(base + x.v if x.op in JUMPS else None)
    stub0 = len(seq)
    for i in range(nf):
        seq += [Ins(OP_CALL, i), Ins(OP_END)]
        tgt += [None, None]
    for k, x in enumerate(seq):
        if x.op == OP_CALL:
            tgt[k] = starts[x.v] + prog.funcs[x.v].entry
    pool: dict[str, int] = {}
    off = 0
    for x in seq:
        if x.op == OP_PUSHS and x.v not in pool:
            pool[x.v] = off
            off += 2 * len(x.v) + 2
    sizes = _layout([Ins(x.op, x.v, _usize(pool[x.v])) if x.op == OP_PUSHS else x for x in seq], tgt)
    code0 = HEADER_SIZE + 4 * ng + 16 * nf
    addr = [code0]
    for k, x in enumerate(seq):
        addr.append(addr[-1] + 1 + sizes[k] + (x.op in TYPED))
    code = bytearray()
    for k, x in enumerate(seq):
        n = sizes[k]
        v = addr[tgt[k]] - addr[k] if tgt[k] is not None else pool[x.v] if x.op == OP_PUSHS else x.v
        code.append(x.op | SIZES.index(n) << 6)
        if n:
            code += int(v).to_bytes(n, 'little', signed=x.op in SIGNED or v < 0)
        if x.op in TYPED:
            code.append(x.t)
    pool_at = code0 + len(code)
    blob = bytearray(b''.join(_wz(s) for s in pool))
    gptr, nptr, tptr = [], [], []
    for s in prog.globals:
        gptr.append(pool_at + len(blob))
        blob += _wz(s)
    for f in prog.funcs:
        nptr.append(pool_at + len(blob))
        blob += _wz(f.name)
    for f in prog.funcs:
        tptr.append(pool_at + len(blob))
        blob += f.types
    name_at = pool_at + len(blob)
    blob += _wz(prog.name)
    end4 = _align(pool_at + len(blob), 4)
    end16 = _align(end4, 16)
    fbase = addr[starts[0]] if nf else addr[len(seq)]
    head = struct.pack('<4s19I', MAGIC, HEADER_SIZE, 0, 0, VERSION, 2, ng, HEADER_SIZE, nf, HEADER_SIZE + 4 * ng,
                       0x200, 0x200, code0, fbase, pool_at, name_at, 0, end4, 0, end16)
    table = struct.pack(f'<{ng}I', *gptr)
    for i, f in enumerate(prog.funcs):
        if len(f.types) > 0xFF or f.signature_flags & 0xFF or not 0 <= f.signature_flags <= 0xFFFFFF00:
            raise ValueError(f'BVM: {f.name}: invalid function signature')
        table += struct.pack('<4I', addr[stub0 + 2 * i] - fbase, nptr[i], tptr[i], len(f.types) | f.signature_flags)
    data = head + table + bytes(code) + bytes(blob)
    return data + bytes([PAD]) * (end16 - len(data))


# stack effect (pushes - pops) of the ops; a call pops its function's parameters, a native as `effects` (NET6) says
STACK: dict[int, int] = {0x01: -1, 0x02: -1, 0x03: 1, 0x04: -1, 0x05: -1, 0x06: -1, 0x07: -1, 0x08: -1, 0x09: 0,
                         0x0A: 0, 0x0B: 0, 0x0C: -1, 0x0D: -1, 0x0E: -1, 0x0F: -1, 0x10: -1, 0x11: 0, 0x12: 0, 0x13: 0,
                         0x14: 1, 0x15: 1, 0x16: -1, 0x17: 1, 0x18: 1, 0x19: -1, 0x1A: 1, 0x1B: 0, 0x1C: 0, 0x1D: -1,
                         0x1E: -1, 0x1F: 0, 0x20: -1, 0x21: -1, 0x22: -1, 0x23: -1, 0x24: -1, 0x25: -1, 0x26: -1,
                         0x27: -1, 0x28: 0, 0x2A: -1, 0x30: 0, 0x31: -1, 0x32: -1, 0x33: 1, 0x34: -2, 0x35: -2,
                         0x36: -2}
# stack effect in EDF6's executor of the natives EDF5-format scripts call (op, id): measured by emulating EDF.dll's
# dispatcher 0x20FF70 (the BVM stack pointer it hands back); 0/10000..10003 take nothing (read no argument); 1/3003
# is supplied by the EDF6VehicleCrew plugin (pops the handle and the radius), not by stock EDF6.
NET6: dict[tuple[int, int], int] = {(0x2C, 1): -1, (0x2C, 2): -3, (0x2C, 3): -1, (0x2C, 5): 0, (0x2C, 9): -1,
    (0x2C, 10): 0, (0x2C, 11): 0, (0x2C, 12): 0, (0x2C, 13): -2, (0x2C, 14): -3, (0x2C, 16): 0, (0x2C, 17): -1,
    (0x2C, 18): -4, (0x2C, 20): -1, (0x2C, 21): 1, (0x2C, 22): 0, (0x2C, 30): 0, (0x2C, 31): -1, (0x2C, 33): -1, (0x2C, 38): -2,
    (0x2C, 39): 0, (0x2C, 50): -3, (0x2C, 51): -1, (0x2C, 52): -1, (0x2C, 100): -2, (0x2C, 102): -1, (0x2C, 103): -1,
    (0x2C, 104): -1, (0x2C, 110): -1, (0x2C, 200): -1, (0x2C, 201): -1, (0x2C, 300): -1, (0x2C, 301): -1,
    (0x2C, 302): -2, (0x2C, 350): -1, (0x2C, 351): -2, (0x2C, 401): -1, (0x2C, 410): 0, (0x2C, 420): -6,
    (0x2C, 800): -3, (0x2C, 900): -2, (0x2C, 901): -4, (0x2C, 902): -4, (0x2C, 910): 0, (0x2C, 1000): -1,
    (0x2C, 1003): 1, (0x2C, 1010): -3, (0x2C, 1011): -6, (0x2C, 1012): -6, (0x2C, 1020): -2, (0x2C, 1021): -1,
    (0x2C, 1022): -5, (0x2C, 1023): -5, (0x2C, 1100): -1, (0x2C, 1140): -4, (0x2C, 1141): -4, (0x2C, 2000): -3,
    (0x2C, 2001): -3, (0x2C, 2002): -6, (0x2C, 2003): -6, (0x2C, 2006): -5, (0x2C, 2022): -6, (0x2C, 2100): -8,
    (0x2C, 2101): -7, (0x2C, 3000): -1, (0x2C, 3019): -2, (0x2C, 3020): -2, (0x2C, 3021): -2, (0x2C, 3022): -1,
    (0x2C, 3023): -1, (0x2C, 3024): -2, (0x2C, 3025): -2, (0x2C, 3040): -2, (0x2C, 3051): -1, (0x2C, 3100): -2,
    (0x2C, 3101): -2, (0x2C, 3102): -2, (0x2C, 3103): 0, (0x2C, 3150): -2, (0x2C, 3151): -2, (0x2C, 3152): -2,
    (0x2C, 3200): -2, (0x2C, 3201): -2, (0x2C, 3202): -1, (0x2C, 3300): -2, (0x2C, 4000): -1, (0x2C, 4002): 0,
    (0x2C, 4010): -1, (0x2C, 4011): -1, (0x2C, 4100): 0, (0x2C, 4101): 0, (0x2C, 4102): -4, (0x2C, 4103): -4,
    (0x2C, 4104): -5, (0x2C, 4105): -5, (0x2C, 4106): -6, (0x2C, 5100): -15, (0x2C, 5101): -13, (0x2C, 5102): -7,
    (0x2C, 5103): -7, (0x2C, 9000): -1, (0x2C, 9001): -2, (0x2C, 9100): -1, (0x2C, 9110): -2, (0x2C, 9112): -3,
    (0x2C, 9113): -2, (0x2C, 9114): -1, (0x2C, 9115): -2, (0x2C, 9120): -1, (0x2C, 9200): -2, (0x2C, 9201): -1,
    (0x2C, 9202): -1, (0x2C, 9300): -1, (0x2C, 9301): -1, (0x2C, 9310): -1, (0x2C, 9400): -1, (0x2C, 10000): 0,
    (0x2C, 10001): 0, (0x2C, 10002): 0, (0x2C, 10003): 0, (0x2D, 0): 0, (0x2D, 1): 0, (0x2D, 2): 1, (0x2D, 102): -2,
    (0x2D, 1000): -6, (0x2D, 3003): -2, (0x2D, 10000): 1}


def stack_check(prog: Program, effects: dict[tuple[int, int], int] | None = None) -> list[str]:
    """Where prog's stack does not balance under `effects` (default NET6): a jump target reached at two depths, the
    epilogue reached with values left, a native of unknown effect. Empty when every path balances."""
    effects = NET6 if effects is None else effects
    out = []
    for f in prog.funcs:
        results = f.results
        depth = {f.entry: 1 + len(f.types)}
        work = [f.entry]
        while work:
            i = work.pop()
            x = f.code[i]
            if x.op in OP_NATIVE:
                e = effects.get((x.op, x.v))
                if e is None:
                    out.append(f'{f.name}: native {x.op - OP_NAT0}/{x.v} of unknown stack effect')
                    continue
            elif x.op == OP_CALL:
                e = -len(prog.funcs[x.v].types) + prog.funcs[x.v].results
            else:
                e = STACK.get(x.op, 0)
            d = depth[i] + e
            succ = [x.v] if x.op == OP_JMP else [x.v, i + 1] if x.op in JUMPS else [] if x.op in (OP_RET, OP_END) \
                else [i + 1]
            for j in succ:
                if j == 0:
                    if d != results:
                        out.append(f'{f.name}: {d} values left at the epilogue (expected {results}; from {i})')
                elif j >= len(f.code):
                    out.append(f'{f.name}: runs off its end at {i}')
                elif j not in depth:
                    depth[j] = d
                    work.append(j)
                elif depth[j] != d:
                    out.append(f'{f.name}: {j} reached at depths {depth[j]} and {d}')
    return out


# what EDF6's executor reads for each native's arguments, bottom to top, and how many values it leaves: p a pointer (a
# string), f a float, i an int (a number, an object handle, a bool), ? not read in the emulated path. Measured by
# emulating the dispatcher 0x20FF70 (the instruction reading each argument slot); 1/3003 is the plugin's; 0/20 copies
# its argument's 32 bits as they are (0x210DB5: into the executor's +0x46C), so takes either. 0/22 only writes
# GS+0x44 (0x210E10); it consumes no value and must not terminate a walk as an unknown native.
SIG6: dict[tuple[int, int], tuple[str, int]] = {(0x2C, 1): ('?', 0), (0x2C, 2): ('pfi', 0), (0x2C, 3): ('i', 0),
    (0x2C, 5): ('', 0), (0x2C, 9): ('f', 0), (0x2C, 10): ('', 0), (0x2C, 11): ('', 0), (0x2C, 12): ('', 0),
    (0x2C, 13): ('pi', 0), (0x2C, 14): ('ppi', 0), (0x2C, 16): ('', 0), (0x2C, 17): ('i', 0), (0x2C, 18): ('????', 0),
    (0x2C, 20): ('?', 0), (0x2C, 21): ('', 1), (0x2C, 22): ('', 0), (0x2C, 30): ('p', 1), (0x2C, 31): ('i', 0), (0x2C, 33): ('i', 0),
    (0x2C, 38): ('ppi', 1), (0x2C, 39): ('p', 1), (0x2C, 50): ('iif', 0), (0x2C, 51): ('i', 0), (0x2C, 52): ('i', 0),
    (0x2C, 100): ('pp', 0), (0x2C, 102): ('p', 0), (0x2C, 103): ('p', 0), (0x2C, 104): ('p', 0), (0x2C, 110): ('p', 0),
    (0x2C, 200): ('f', 0), (0x2C, 201): ('i', 0), (0x2C, 300): ('p', 0), (0x2C, 301): ('f', 0), (0x2C, 302): ('pf', 0),
    (0x2C, 350): ('p', 0), (0x2C, 351): ('pp', 0), (0x2C, 401): ('p', 0), (0x2C, 410): ('', 0),
    (0x2C, 420): ('ifffff', 0), (0x2C, 800): ('pff', 0), (0x2C, 900): ('pf', 0), (0x2C, 901): ('pfii', 0),
    (0x2C, 902): ('piff', 0), (0x2C, 910): ('', 0), (0x2C, 1000): ('p', 0), (0x2C, 1003): ('', 1),
    (0x2C, 1010): ('ppfi', 1), (0x2C, 1011): ('pfppifi', 1), (0x2C, 1012): ('pfpifi', 0), (0x2C, 1020): ('ppf', 1),
    (0x2C, 1021): ('pp', 1), (0x2C, 1022): ('pppppf', 1), (0x2C, 1023): ('pppppf', 1), (0x2C, 1100): ('i', 0),
    (0x2C, 1140): ('ifpf', 0), (0x2C, 1141): ('ifpf', 0), (0x2C, 2000): ('ppfi', 1), (0x2C, 2001): ('ppfi', 1),
    (0x2C, 2002): ('pfpifi', 0), (0x2C, 2003): ('pfpifi', 0), (0x2C, 2006): ('ppifi', 0), (0x2C, 2022): ('pfpifi', 0),
    (0x2C, 2100): ('iipifffi', 0), (0x2C, 2101): ('iipiffi', 0), (0x2C, 3000): ('i', 0), (0x2C, 3019): ('if', 0),
    (0x2C, 3020): ('if', 0), (0x2C, 3021): ('ii', 0), (0x2C, 3022): ('i', 0), (0x2C, 3023): ('i', 0),
    (0x2C, 3024): ('if', 0), (0x2C, 3025): ('if', 0), (0x2C, 3040): ('ii', 0), (0x2C, 3051): ('i', 0),
    (0x2C, 3100): ('if', 0), (0x2C, 3101): ('ip', 0), (0x2C, 3102): ('ip', 0), (0x2C, 3103): ('i', 1),
    (0x2C, 3150): ('if', 0), (0x2C, 3151): ('ii', 0), (0x2C, 3152): ('ii', 0), (0x2C, 3200): ('ii', 0),
    (0x2C, 3201): ('ii', 0), (0x2C, 3202): ('i', 0), (0x2C, 3300): ('iii', 1), (0x2C, 4000): ('p', 0),
    (0x2C, 4002): ('', 0), (0x2C, 4010): ('i', 0), (0x2C, 4011): ('f', 0), (0x2C, 4100): ('', 0), (0x2C, 4101): ('', 0),
    (0x2C, 4102): ('ippf', 0), (0x2C, 4103): ('ippf', 0), (0x2C, 4104): ('ippff', 0), (0x2C, 4105): ('iippf', 0),
    (0x2C, 4106): ('iippff', 0), (0x2C, 5100): ('ffffffffffffiff', 0), (0x2C, 5101): ('fffffffffifff', 0),
    (0x2C, 5102): ('fifffff', 0), (0x2C, 5103): ('fifffff', 0), (0x2C, 9000): ('f', 0), (0x2C, 9001): ('if', 0),
    (0x2C, 9100): ('f', 0), (0x2C, 9110): ('ii', 0), (0x2C, 9112): ('pii', 0), (0x2C, 9113): ('ii', 0),
    (0x2C, 9114): ('i', 0), (0x2C, 9115): ('ii', 0), (0x2C, 9120): ('i', 0), (0x2C, 9200): ('if', 0),
    (0x2C, 9201): ('i', 0), (0x2C, 9202): ('i', 0), (0x2C, 9300): ('i', 0), (0x2C, 9301): ('i', 0),
    (0x2C, 9310): ('i', 0), (0x2C, 9400): ('p', 0), (0x2C, 10000): ('', 0), (0x2C, 10001): ('', 0),
    (0x2C, 10002): ('', 0), (0x2C, 10003): ('', 0), (0x2D, 0): ('', 0), (0x2D, 1): ('i', 1), (0x2D, 2): ('', 1),
    (0x2D, 102): ('ff', 0), (0x2D, 1000): ('pfpfif', 0), (0x2D, 3003): ('if', 0), (0x2D, 10000): ('', 1)}


def _typed_result(x: Ins) -> str:
    """What an op leaves on the stack: f float, i int, s string, ? unknown (a variable, a call's result)."""
    if x.op == OP_PUSHS:
        return 's'
    if x.op == OP_PUSH:
        return 'f' if x.n == 4 else 'i'
    if x.op in (OP_PUSH1, OP_PUSHLA, 0x1D, 0x1E, 0x1F, 0x08, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12):
        return 'i'
    if x.op == 0x13:
        return 'f'
    if x.op in (0x04, 0x05, 0x06, 0x07, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25):
        return 'f' if x.t & 3 else 'i'
    if x.op in (0x09, 0x0A, 0x0B):
        return 'f' if x.t & 2 else 'i'
    return '?'


_ACCEPTS = {'p': 's?', 'f': 'f?', 'i': 'i?', '?': 'sfi?'}


@dataclass(frozen=True)
class Arg:
    """A stack value's conservative type and exact string, when every path agrees. `literals` retains every
    possible literal across control-flow joins; `alternatives` also keeps their types so a bad predecessor is not
    hidden by an unknown value. These finite sets come only from instructions in the input program."""
    t: str
    s: str | None = None
    alternatives: frozenset[tuple[str, str | None]] = field(default_factory=frozenset)

    @property
    def values(self) -> frozenset[tuple[str, str | None]]:
        return self.alternatives or frozenset({(self.t, self.s)})

    @property
    def literals(self) -> frozenset[str]:
        return frozenset(s for t, s in self.values if t == 's' and s is not None)


def _join_arg(a: Arg, b: Arg) -> Arg:
    values = a.values | b.values
    if len(values) == 1:
        return Arg(*next(iter(values)))
    types = {t for t, _ in values}
    return Arg(next(iter(types)) if len(types) == 1 else '?', None, values)


_UNKNOWN = Arg('?')


def _walk(prog: Program, sigs: dict[tuple[int, int], tuple[str, int]],
          visit: Callable[[Function, int, Ins, list[Arg] | None], None]) -> None:
    """Every reachable native call once, after merging all its predecessors to a fixed point. Ambiguous values
    retain their alternatives instead of choosing the first path. An unknown native or too few native arguments
    stops that path and visits it with None; inconsistent stack depths and non-native underflow are rejected."""
    for f in prog.funcs:
        _ = f.results  # do not analyse an unknown signature as if it were void
        stacks: dict[int, list[Arg]] = {f.entry: [_UNKNOWN] * (1 + len(f.types))}
        calls: dict[int, list[Arg] | None] = {}
        work = [f.entry]
        while work:
            i = work.pop()
            st = list(stacks[i])
            x = f.code[i]

            def require(n: int) -> None:
                if len(st) < n:
                    raise ValueError(f'BVM: {f.name} {i}: stack underflow ({len(st)} values, needs {n})')

            if x.op in OP_NATIVE:
                sig = sigs.get((x.op, x.v))
                if sig is None:
                    calls[i] = None
                    continue
                want, results = sig
                if len(st) < len(want):
                    calls[i] = None
                    continue
                calls[i] = st[len(st) - len(want):] if want else []
                del st[len(st) - len(want):]
                st += [_UNKNOWN] * results
            elif x.op == OP_CALL:
                n = len(prog.funcs[x.v].types)
                require(n)
                del st[len(st) - n:]
                st += [_UNKNOWN] * prog.funcs[x.v].results
            elif x.op == 0x03:
                require(1)
                st.append(st[-1])
            elif x.op == OP_STOREI:
                require(2)
                st[-2:] = [st[-1]]
            else:
                e = STACK.get(x.op, 0)
                pops = {0: 1, 1: 0, -1: 2, -2: 2}.get(e, 0) if x.op not in (OP_PUSHG, OP_PUSH, OP_PUSHL, OP_PUSHLA,
                                                                             OP_PUSHS, OP_PUSH1) else 0
                if x.op in (OP_STOREG, OP_STOREL, OP_POP, OP_JZ, 0x27, OP_RET, 0x31, 0x32):
                    pops = 1
                elif x.op in (OP_JNE, 0x35, OP_STOREIND):
                    pops = 2
                elif x.op in (OP_FPADD, OP_FPSUB, OP_JMP, OP_END):
                    pops = 0
                if pops:
                    require(pops)
                    del st[len(st) - pops:]
                if e + pops > 0:
                    st.append(Arg(_typed_result(x), x.v if x.op == OP_PUSHS and isinstance(x.v, str) else None))
            succ = [x.v] if x.op == OP_JMP else [x.v, i + 1] if x.op in JUMPS else [] if x.op in (OP_RET, OP_END) \
                else [i + 1]
            for j in succ:
                if not 0 < j < len(f.code):
                    continue
                if j not in stacks:
                    stacks[j] = list(st)
                    work.append(j)
                    continue
                previous = stacks[j]
                if len(previous) != len(st):
                    raise ValueError(f'BVM: {f.name} {j}: reached at stack depths {len(previous)} and {len(st)}')
                merged = [_join_arg(a, b) for a, b in zip(previous, st)]
                if merged != previous:
                    stacks[j] = merged
                    work.append(j)
        for i in sorted(calls):
            visit(f, i, f.code[i], calls[i])


def type_check(prog: Program, sigs: dict[tuple[int, int], tuple[str, int]] | None = None) -> list[str]:
    """Each native call whose arguments, as the script pushes them, are not of the types EDF6's handler reads (SIG6):
    a string literal where a number is read, a float where an int is, and so on. A value whose type the script does not
    show (a variable, a native's result) fits anything."""
    sigs = SIG6 if sigs is None else sigs
    out: list[str] = []

    def visit(f: Function, i: int, x: Ins, got: list[Arg] | None) -> None:
        if got is None:
            why = 'has no signature' if (x.op, x.v) not in sigs else 'with too few values on the stack'
            out.append(f'{f.name} {i}: native {x.op - OP_NAT0}/{x.v} {why}')
            return
        want = sigs[(x.op, x.v)][0]
        for k, (w, g) in enumerate(zip(want, got)):
            for passed in sorted({t for t, _ in g.values} - set(_ACCEPTS[w])):
                out.append(f'{f.name} {i}: native {x.op - OP_NAT0}/{x.v} argument {k + 1} of {len(want)}: '
                           f'reads {w}, the script passes {passed}')
    _walk(prog, sigs, visit)
    return out


def native_calls(prog: Program, wanted: set[tuple[int, int]],
                 sigs: dict[tuple[int, int], tuple[str, int]] | None = None) -> list[tuple[str, int, Ins, list[Arg]]]:
    """(function name, index, instruction, arguments) of every call of a native in `wanted` ((op, id) pairs), each once,
    with the values the script passes it (Arg.s: an exact literal only when all paths agree; Arg.literals: every
    possible literal on those paths). A wanted native
    without a signature in `sigs` (SIG6), or reached with too few values on the stack, raises ValueError: the caller
    asked for arguments this walk cannot give."""
    sigs = SIG6 if sigs is None else sigs
    out: dict[tuple[str, int], tuple[str, int, Ins, list[Arg]]] = {}

    def visit(f: Function, i: int, x: Ins, got: list[Arg] | None) -> None:
        if (x.op, x.v) not in wanted:
            return
        if got is None:
            raise ValueError(f'{f.name} {i}: native {x.op - OP_NAT0}/{x.v}: no arguments to read (signature / stack)')
        out.setdefault((f.name, i), (f.name, i, x, list(got)))
    _walk(prog, sigs, visit)
    return [out[k] for k in sorted(out, key=lambda k: ([g.name for g in prog.funcs].index(k[0]), k[1]))]
