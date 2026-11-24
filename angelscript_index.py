"""Decode the stock EDF6 AngelScript registration site and VM dispatch tables."""

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
from pathlib import Path
import re
import struct
import zipfile

import capstone
from capstone import x86
import pefile

from verify_install import gate_or_exit, write_provenance


from edf6re_lib.paths import out_root

ROOT = Path(__file__).resolve().parent
OUT = out_root()   # every generated artifact lives here: $EDF6RE_OUT or <repo>/out (git-ignored)
IMAGE_SHA = '0d5092393a1b9d8f1b75b0c93d8a8f65615a36a92c46e40349c2b66c733d0916'
SDK_SHA = '54bc6126d2ba2509f3916ff139758d3c3c2185dddb521fc040110c5afde6000a'
REGISTRATION = (0x1e31f0, 0x1f53c0)
VM = (0x11e7e20, 0x11eab50)
VM_TABLE = 0x11eab50
POWER_TABLE = 0x11eaf50
RSP, RBP = 0x8000000000000000, 0x9000000000000000
VOLATILE = ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11')
# vtable offsets in the binary; order independently matches asIScriptEngine 2.28.2.
SIGNATURES = {
    0x48: ('global_function', 'rdx', None, 'r8', 'r9'),
    0x90: ('object_type', 'rdx', None, None, None),
    0xa0: ('object_method', 'r8', 'rdx', 'r9', RSP + 0x20),
    0xa8: ('object_behaviour', 'r9', 'rdx', RSP + 0x20, RSP + 0x28),
    0xf8: ('enum', 'rdx', None, None, None),
    0x100: ('enum_value', 'r8', 'rdx', None, None),
    0x178: ('namespace', 'rdx', None, None, None),
}
# asSFuncPtr helpers. The registration code builds each function pointer argument by calling a small compiled
# AngelScript helper (AngelScript is zlib-licensed; these are MSVC's builds of its asSFuncPtr / asFUNCTION helpers as
# EDF.dll links them) that stores the function address from RDX into the first eight bytes of the asSFuncPtr object at
# RCX and returns that object in RAX. They are recognised by that behaviour (see is_pointer_helper), not by their bytes.
POINTER_HELPER_LIMIT = 64      # instructions; the helpers are straight-line moves
POINTER_HELPER_OBJECT = 0x40   # bytes of the asSFuncPtr object the helper may write
REGISTER_GROUPS = (
    ('rax', 'eax', 'ax', 'al'), ('rbx', 'ebx', 'bx', 'bl'),
    ('rcx', 'ecx', 'cx', 'cl'), ('rdx', 'edx', 'dx', 'dl'),
    ('rsi', 'esi', 'si', 'sil'), ('rdi', 'edi', 'di', 'dil'),
    *((f'r{i}', f'r{i}d', f'r{i}w', f'r{i}b') for i in range(8, 16)),
)
ALIASES = {alias: group[0] for group in REGISTER_GROUPS for alias in group}
REGISTER_WIDTHS = {alias: (8, 4, 2, 1)[index] for group in REGISTER_GROUPS for index, alias in enumerate(group)}


def hx(value):
    return '' if value is None else f'0x{value:08X}'


def is_pointer_helper(image, rva):
    """Whether the code at rva behaves as an asSFuncPtr helper: run it on concrete values (only mov / movzx between
    registers, immediates and [base + disp] memory, ending in ret) and check that it wrote RDX into [RCX..RCX+8),
    wrote nothing but that object and its own home space, and returned RCX."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    obj, pointer, stack = 0x10000, 0x1122334455667788, 0x80000
    registers = {'rcx': obj, 'rdx': pointer, 'rsp': stack}
    memory = {}

    def address(ins, operand):
        mem = operand.mem
        if mem.index or mem.segment or not mem.base:
            return None
        base = registers.get(ins.reg_name(mem.base))
        return None if base is None else base + mem.disp

    def read(ins, operand):
        if operand.type == x86.X86_OP_IMM:
            return operand.imm & ((1 << (8 * operand.size)) - 1)
        if operand.type == x86.X86_OP_REG:
            name = ins.reg_name(operand.reg)
            value = registers.get(ALIASES.get(name))
            return None if value is None else value & ((1 << (8 * REGISTER_WIDTHS[name])) - 1)
        where = address(ins, operand)
        if where is None or any(where + i not in memory for i in range(operand.size)):
            return None
        return int.from_bytes(bytes(memory[where + i] for i in range(operand.size)), 'little')

    for count, ins in enumerate(decoder.disasm(image[rva:rva + 16 * POINTER_HELPER_LIMIT], rva)):
        if count >= POINTER_HELPER_LIMIT:
            return False
        if ins.mnemonic == 'ret':
            if registers.get('rax') != obj or any(obj + i not in memory for i in range(8)):
                return False
            stored = int.from_bytes(bytes(memory[obj + i] for i in range(8)), 'little')
            # Only the object and the caller-provided home space (rsp+8 .. rsp+0x28 at entry) may be written.
            contained = all(obj <= a < obj + POINTER_HELPER_OBJECT or stack + 8 <= a < stack + 0x28 for a in memory)
            return stored == pointer and contained
        if ins.mnemonic not in ('mov', 'movzx') or len(ins.operands) != 2:
            return False
        destination, source = ins.operands
        value = read(ins, source)
        if value is None:
            return False
        if destination.type == x86.X86_OP_REG:
            name = ins.reg_name(destination.reg)
            full = ALIASES.get(name)
            if full is None:
                return False
            if REGISTER_WIDTHS[name] >= 4:
                registers[full] = value
            else:
                mask = (1 << (8 * REGISTER_WIDTHS[name])) - 1
                registers[full] = (registers.get(full, 0) & ~mask) | (value & mask)
        elif destination.type == x86.X86_OP_MEM:
            where = address(ins, destination)
            if where is None:
                return False
            for i in range(destination.size):
                memory[where + i] = (value >> (8 * i)) & 0xff
        else:
            return False
    return False


class RegistrationTrace:
    def __init__(self, image, base, code, data):
        self.image = image
        self.base = base
        self.code = code
        self.data = data
        self.registers = {'rsp': RSP, 'rbp': RBP}
        self.memory = {}
        self.namespace = ''
        self.helpers = {}

    def pointer_helper(self, rva):
        if rva not in self.helpers:
            self.helpers[rva] = self.executable(rva + self.base) and is_pointer_helper(self.image, rva)
        return self.helpers[rva]

    def stack_read(self, address, size):
        if address is not None and all(address + i in self.memory for i in range(size)):
            return int.from_bytes(bytes(self.memory[address + i] for i in range(size)), 'little')
        return None

    def stack_write(self, address, size, value):
        if address is None or not self.is_stack(address):
            return
        for i in range(size):
            if isinstance(value, int):
                self.memory[address + i] = (value >> (i * 8)) & 0xff
            else:
                self.memory.pop(address + i, None)

    @staticmethod
    def is_stack(address):
        return isinstance(address, int) and any(base - 0x10000 <= address < base + 0x10000 for base in (RSP, RBP))

    def address(self, ins, operand):
        mem = operand.mem
        if mem.base == x86.X86_REG_RIP:
            return self.base + ins.address + ins.size + mem.disp
        if not mem.index:
            base = self.registers.get(ins.reg_name(mem.base))
            if isinstance(base, int):
                return base + mem.disp
        return None

    def value(self, ins, operand):
        if operand.type == x86.X86_OP_IMM:
            return operand.imm
        if operand.type == x86.X86_OP_REG:
            name = ins.reg_name(operand.reg)
            value = self.registers.get(ALIASES.get(name, name))
            if isinstance(value, int):
                return value & ((1 << (8 * operand.size)) - 1)
            return value
        if operand.type == x86.X86_OP_MEM:
            base = ins.reg_name(operand.mem.base)
            if base == 'rsi' and not operand.mem.index and operand.mem.disp == 0:
                return ('engine_vtable',)
            if self.registers.get(base) == ('engine_vtable',) and not operand.mem.index:
                return ('slot', operand.mem.disp)
            return self.stack_read(self.address(ins, operand), operand.size)
        return None

    def apply(self, ins):
        operands = ins.operands
        if not operands:
            return
        dest = operands[0]
        value = None
        if ins.mnemonic in ('mov', 'movzx'):
            value = self.value(ins, operands[1])
        elif ins.mnemonic == 'lea':
            value = self.address(ins, operands[1])
        elif ins.mnemonic == 'xor' and operands[0].type == operands[1].type == x86.X86_OP_REG:
            if operands[0].reg == operands[1].reg:
                value = 0
        if dest.type == x86.X86_OP_MEM and dest.access & capstone.CS_AC_WRITE:
            self.stack_write(self.address(ins, dest), dest.size, value)
        for reg in ins.regs_access()[1]:
            name = ins.reg_name(reg)
            full = ALIASES.get(name, name)
            if full in ('rsp', 'rbp'):
                continue
            if dest.type == x86.X86_OP_REG and reg == dest.reg and dest.size >= 4 and value is not None:
                self.registers[full] = value
            else:
                self.registers.pop(full, None)

    def argument(self, location, size=8):
        if isinstance(location, int):
            return self.stack_read(location, size)
        return self.registers.get(location)

    def executable(self, address):
        return isinstance(address, int) and self.code[0] <= address - self.base < self.code[1]

    def string(self, address):
        if not isinstance(address, int):
            return ''
        rva = address - self.base
        if self.data[0] <= rva < self.data[1]:
            result = self.image[rva:rva + 256].split(b'\0', 1)[0]
            if all(32 <= byte < 127 for byte in result):
                return result.decode('ascii')
        return ''

    def call(self, ins):
        operand = ins.operands[0]
        target = self.value(ins, operand)
        result = None
        row = None
        if isinstance(target, tuple) and target[0] == 'slot':
            slot = target[1]
            if slot not in SIGNATURES:
                raise ValueError(f'Unexpected registration vtable slot at {ins.address:#x}: {slot:#x}')
            kind, decl_arg, type_arg, pointer_arg, conv_arg = SIGNATURES[slot]
            declaration = self.string(self.argument(decl_arg))
            owner = self.string(self.argument(type_arg))
            pointer = self.argument(pointer_arg)
            fn = self.stack_read(pointer, 8) if self.is_stack(pointer) else None
            encoded_conv = self.argument(conv_arg, 4)
            conv = encoded_conv & 0xffffffff if isinstance(encoded_conv, int) else None
            value = self.registers.get('r9' if kind == 'enum_value' else 'r8')
            if kind not in ('enum_value', 'object_type', 'object_behaviour'):
                value = None
            if kind == 'enum_value' and isinstance(value, int) and value & 0x80000000:
                value -= 0x100000000
            if kind == 'namespace':
                self.namespace = declaration
            flags = self.registers.get('r9') if kind == 'object_type' else None
            row = (hx(ins.address), kind, hx(slot), owner, declaration,
                   hx(fn - self.base if self.executable(fn) else None), conv, value, flags, self.namespace)
        elif operand.type == x86.X86_OP_IMM:
            if self.pointer_helper(operand.imm):
                destination, fn = self.registers.get('rcx'), self.registers.get('rdx')
                if self.is_stack(destination) and self.executable(fn):
                    self.stack_write(destination, 8, fn)
                    result = destination
        for reg in VOLATILE:
            self.registers.pop(reg, None)
        if result is not None:
            self.registers['rax'] = result
        return row


def registration_rows(pe, image):
    def extent(name):
        section = next(section for section in pe.sections if section.Name.rstrip(b'\0') == name)
        return section.VirtualAddress, section.VirtualAddress + section.Misc_VirtualSize

    trace = RegistrationTrace(image, pe.OPTIONAL_HEADER.ImageBase, extent(b'.text'), extent(b'.rdata'))
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    start, end = REGISTRATION
    expected = start
    for ins in decoder.disasm(image[start:end], start):
        if ins.address != expected or ins.group(capstone.CS_GRP_JUMP):
            raise ValueError(f'Unexpected registration flow at {ins.address:#x}')
        if ins.mnemonic == 'call':
            row = trace.call(ins)
            if row is not None:
                yield row
        else:
            trace.apply(ins)
        expected += ins.size
    if expected != end:
        raise ValueError(f'Registration disassembly stopped at {expected:#x}, expected {end:#x}')


def dispatch_rows(image, sdk):
    with zipfile.ZipFile(sdk) as archive:
        header = archive.read('sdk/angelscript/include/angelscript.h').decode('ascii', errors='replace')
    values = {int(number): name for name, number in re.findall(r'\basBC_(\w+)\s*=\s*(\d+)', header)}
    classes = dict(re.findall(r'\basBCINFO\(\s*(\w+)\s*,\s*(\w+)\s*,', header))
    for opcode in range(256):
        slot = VM_TABLE + opcode * 4
        rva, = struct.unpack_from('<I', image, slot)
        if opcode < 200 and not (VM[0] <= rva < VM[1] and values[opcode] in classes):
            raise ValueError(f'Unrecognized opcode slot {opcode}: {rva:#x}')
        status = 'defined_in_2.28.2' if opcode < 200 else ('zero_entry' if not rva else 'reserved_compiled_entry')
        yield (opcode, f'0x{opcode:02X}', values[opcode] if opcode < 200 else '',
               classes.get(values.get(opcode), '') if opcode < 200 else '', hx(slot), hx(rva), status)


def upstream_dispatch_sites(sdk, opcodes):
    member = 'sdk/angelscript/source/as_context.cpp'
    with zipfile.ZipFile(sdk) as archive:
        source = archive.read(member).decode('utf-8')
    lines = source.splitlines()
    first = next(i for i, line in enumerate(lines, 1) if line.startswith('void asCContext::ExecuteNext()'))
    cases = {}
    for n, line in enumerate(lines[first:], first + 1):
        if match := re.search(r'\bcase asBC_(\w+)\s*:', line):
            cases.setdefault(match[1], n)
    for opcode, _, name, _, _, rva, status in opcodes:
        if status == 'defined_in_2.28.2':
            yield opcode, name, rva, member, cases[name]


def write_rows(path, header, rows):
    with path.open('x', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def write_annotated_asm(path, image, bounds, labels):
    start, end = bounds
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    with path.open('x', encoding='utf-8', newline='\n') as f:
        f.write(f'; EDF.dll SHA-256 {IMAGE_SHA}\n; Code RVA range [{hx(start)}, {hx(end)})\n')
        expected = start
        for rva, size, mnemonic, operands in decoder.disasm_lite(image[start:end], start):
            if rva != expected:
                raise ValueError(f'Missing instruction bytes at {expected:#x}')
            for label in labels.get(rva, ()):
                f.write(f'\n; {label}\n')
            raw = image[rva:rva + size].hex(' ').upper()
            f.write(f'{rva:08X}  {raw:44}  {mnemonic:12} {operands}'.rstrip() + '\n')
            expected = rva + size
        if expected != end:
            raise ValueError(f'Decode ended at {expected:#x}; expected {end:#x}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dll', type=Path)
    parser.add_argument('--sdk', type=Path, default=OUT / '_cache/angelscript_2.28.2.zip')
    parser.add_argument('--output', type=Path, default=OUT / 'angelscript')
    parser.add_argument('--allow-unofficial', action='store_true', help='generate from unverified game files; recorded in provenance.json')
    args = parser.parse_args()
    provenance = gate_or_exit(parser, args.dll.parent, (args.dll.name,), args.allow_unofficial, 'angelscript_index.py')
    raw = args.dll.read_bytes()
    if hashlib.sha256(raw).hexdigest() != IMAGE_SHA or hashlib.sha256(args.sdk.read_bytes()).hexdigest() != SDK_SHA:
        parser.error('This extraction is pinned to the documented EDF.dll and AngelScript 2.28.2 archive')
    pe = pefile.PE(data=raw, fast_load=True)
    image = pe.get_memory_mapped_image()
    rows = list(registration_rows(pe, image))
    opcodes = list(dispatch_rows(image, args.sdk))
    vm_labels = defaultdict(list)
    for _, opcode, name, fmt, _, handler, status in opcodes:
        if status == 'defined_in_2.28.2':
            vm_labels[int(handler, 16)].append(f'{opcode} {name} ({fmt})')
    registration_labels = {}
    for call, kind, _, owner, declaration, function, *_ in rows:
        name = f'{owner} :: {declaration}' if owner else declaration
        registration_labels[int(call, 16)] = [f'{kind}  {name}' + (f' -> {function}' if function else '')]
    args.output.mkdir(parents=True, exist_ok=False)
    write_provenance(args.output, provenance)
    (args.output / 'sha256.txt').write_text(IMAGE_SHA + '\n', encoding='ascii')
    write_rows(args.output / 'registrations.tsv',
               ('call_rva', 'kind', 'vtable_offset', 'owner', 'declaration', 'implementation_rva', 'call_convention',
                'value', 'object_flags', 'namespace'), rows)
    write_rows(args.output / 'opcodes.tsv',
               ('opcode', 'hex', 'name', 'operand_format', 'dispatch_slot_rva', 'handler_rva', 'status'), opcodes)
    write_rows(args.output / 'upstream-opcode-lines.tsv', ('opcode', 'name', 'handler_rva', 'sdk_file', 'line'),
               upstream_dispatch_sites(args.sdk, opcodes))
    write_rows(args.output / 'pow-dispatch.tsv', ('index', 'dispatch_slot_rva', 'handler_rva'),
               ((index, hx(POWER_TABLE + index * 4), hx(rva))
                for index, rva in enumerate(struct.unpack_from('<6I', image, POWER_TABLE))))
    write_annotated_asm(args.output / 'registrations.asm', image, REGISTRATION, registration_labels)
    write_annotated_asm(args.output / 'handlers.asm', image, VM, vm_labels)
    print(Counter(row[1] for row in rows))
    print('Native mappings:', sum(bool(row[5]) for row in rows), '/', sum(row[1] in ('global_function', 'object_method', 'object_behaviour') for row in rows))
    print('Declarations without a decoded string:', sum(not row[4] for row in rows if row[1] != 'namespace'))
    print('Opcode slots:', len(opcodes))


if __name__ == '__main__':
    main()
