"""Trace stock BVM dispatcher stack operations with synthetic x64 fixtures."""

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import struct

import capstone
from capstone import x86
import pefile
import unicorn as ucapi
from unicorn import x86_const as xr

from verify_install import gate_or_exit, write_provenance


from edf6re_lib.paths import out_root

ROOT = Path(__file__).resolve().parent
OUT = out_root()   # every generated artifact lives here: $EDF6RE_OUT or <repo>/out (git-ignored)
SHA256 = '0d5092393a1b9d8f1b75b0c93d8a8f65615a36a92c46e40349c2b66c733d0916'
BEGIN, END, COMMIT = 0x20FF70, 0x2148BA, 0x2100C9
TABLE0_JUMP, TABLE1_JUMP = 0x21016D, 0x210014
HEAP, CPU_STACK, SIZE = 0x100000000, 0x200000000, 0x20000
VM_STACK = HEAP + 0x8000
SCRIPT, PROCESS, OBJECT, VTABLE, STRING = (HEAP + p for p in (0x1000, 0x3000, 0x5000, 0x7000, 0xA000))
STACK_TOP = CPU_STACK + 0x10008
STOP = CPU_STACK + 0x100
WIDTH = 8
REGISTERS = {name: getattr(xr, 'UC_X86_REG_' + name.upper())
             for name in ('rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15','rip')}


def signed_hex(value):
    return f'{value:#x}'


class Dispatcher:
    def __init__(self, dll):
        raw = dll.read_bytes()
        if hashlib.sha256(raw).hexdigest() != SHA256:
            raise ValueError('Unsupported EDF.dll SHA-256')
        pe = pefile.PE(data=raw, fast_load=True)
        self.image = pe.get_memory_mapped_image()
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.uc = ucapi.Uc(ucapi.UC_ARCH_X86, ucapi.UC_MODE_64)
        self.uc.mem_map(self.base, (len(self.image) + 4095) & ~4095)
        self.uc.mem_write(self.base, self.image)
        self.uc.mem_map(HEAP, SIZE)
        self.uc.mem_map(CPU_STACK, SIZE)
        self.decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.decoder.detail = True
        self.instructions = {}
        self.dirty = set()
        self.uc.hook_add(ucapi.UC_HOOK_CODE, self.on_instruction)
        self.uc.hook_add(ucapi.UC_HOOK_MEM_READ | ucapi.UC_HOOK_MEM_WRITE, self.on_memory)
        self.uc.hook_add(ucapi.UC_HOOK_MEM_INVALID, self.on_invalid)
        self.context = self.uc.context_save()

    def read(self, name):
        return self.uc.reg_read(REGISTERS[name])

    def write(self, name, value):
        self.uc.reg_write(REGISTERS[name], value)

    def put(self, addr, fmt, *values):
        self.uc.mem_write(addr, struct.pack(fmt, *values))

    def init(self, table, number, fixture):
        values, self.stub_result, suppress, online = fixture
        self.uc.context_restore(self.context)
        for page in self.dirty:
            raw = self.image[page:page + 4096]
            self.uc.mem_write(self.base + page, raw.ljust(4096, b'\0'))
        self.dirty.clear()
        for addr in (HEAP, CPU_STACK):
            self.uc.mem_write(addr, bytes(SIZE))
        self.put(STACK_TOP, '<Q', STOP)
        self.put(STACK_TOP + 0x28, '<I', number)
        self.put(SCRIPT - 0x30, '<Q', VTABLE)
        self.put(SCRIPT + 0x40, '<Q', OBJECT)
        self.put(SCRIPT + 0x108, '<Q', HEAP + 0xB000)
        self.put(HEAP + 0xB008, '<Q', HEAP + 0xB100)
        self.put(OBJECT, '<Q', VTABLE)
        self.put(PROCESS + 0x68, '<B', suppress)
        self.put(PROCESS + 0x98, '<Q', VM_STACK)
        self.put(self.base + 0x20B2890, '<Q', HEAP + 0xC000)
        self.put(HEAP + 0xC000 + 0x38, '<i', 0 if online else -1)
        self.put(self.base + 0x20B2950, '<Q', HEAP + 0x10000)
        self.put(self.base + 0x20B29C8, '<Q', HEAP + 0x11000)
        self.put(self.base + 0x20B2AC8, '<Q', HEAP + 0x12000)
        self.uc.mem_write(STRING, b'F\x00I\x00X\x00\x00\x00')
        self.uc.mem_write(VTABLE, struct.pack('<Q', STOP) * 128)
        for i in range(24):
            value = values[i % len(values)]
            self.put(VM_STACK - i * WIDTH, '<Q', value)
        for reg, val in (('rcx',SCRIPT),('rdx',PROCESS),('r8',VM_STACK),('r9',table),('rsp',STACK_TOP)):
            self.write(reg,val)
        self.commit = None
        self.entry = None
        self.reads = []
        self.writes = []
        self.calls = []
        self.path = []
        self.failure = ''
        self.opaque_stack_calls = []

    def instruction(self, rva, size):
        if rva not in self.instructions:
            self.instructions[rva] = next(self.decoder.disasm(self.image[rva:rva + size], rva))
        return self.instructions[rva]

    def on_instruction(self, _uc, address, size, _data):
        rva = address - self.base
        if address == STOP:
            self.uc.emu_stop()
            return
        if not BEGIN <= rva < END:
            self.failure = f'out_of_dispatcher at {address:#x}'
            self.uc.emu_stop()
            return
        self.path.append(rva)
        if rva == COMMIT:
            self.commit = self.read('rdx')
            self.uc.emu_stop()
            return
        ins = self.instruction(rva, size)
        if rva == TABLE0_JUMP:
            self.entry = self.read('rcx') - self.base
        elif rva == TABLE1_JUMP:
            self.entry = self.read('rax') - self.base
        elif ins.mnemonic == 'call':
            if ins.operands[0].type == x86.X86_OP_IMM:
                target = signed_hex(ins.operands[0].imm)
            else:
                target = ins.op_str
            self.calls.append((rva,target))
            if rva != 0x2100D8:
                for register in ('rcx','rdx','r8','r9'):
                    value = self.read(register)
                    if VM_STACK - 24 * WIDTH < value <= VM_STACK + 16:
                        self.opaque_stack_calls.append((rva,register,value-VM_STACK))
            self.write('rax', self.stub_result)
            self.write('rip', address + size)

    def on_memory(self, _uc, access, address, size, _value, _data):
        if access == ucapi.UC_MEM_WRITE and self.base <= address < self.base + len(self.image):
            self.dirty.add((address - self.base) & ~4095)
            self.dirty.add((address + size - 1 - self.base) & ~4095)
        if not VM_STACK - 24 * WIDTH < address <= VM_STACK + 16:
            return
        rva = self.read('rip') - self.base
        if access == ucapi.UC_MEM_WRITE:
            self.writes.append((address-VM_STACK,size,rva))
        elif address <= VM_STACK:
            ins = self.instructions[rva]
            # Eight-byte loads identify storage width. The caller can be a string,
            # object address or an opaque 64-bit value.
            kind = 'f' if ins.mnemonic in ('movss','comiss','ucomiss','mulss','addss','subss','divss') else (
                'q' if size == 8 else ('i' if size <= 4 else '?'))
            self.reads.append((address-VM_STACK,size,kind,rva))

    def on_invalid(self, _uc, access, address, size, _value, _data):
        self.failure = f'invalid memory {access} at {address:#x} size={size}; rva={self.read("rip")-self.base:#x}'
        return False

    def run(self, table, number, fixture):
        self.init(table, number, fixture)
        try:
            self.uc.emu_start(self.base + BEGIN, STOP, count=2000)
        except ucapi.UcError as exc:
            if not self.failure:
                self.failure = str(exc)
        delta = None
        if self.commit is not None and (self.commit - VM_STACK) % WIDTH == 0:
            delta = (self.commit - VM_STACK) // WIDTH
        return dict(entry=self.entry, delta=delta, reads=self.reads, writes=self.writes,
                    calls=self.calls, opaque=self.opaque_stack_calls, failure=self.failure,
                    last=self.path[-1] if self.path else None)


FIXTURES = {
    'zero': ((0,), 0, 0, False),
    'one': ((1,), 1, 0, False),
    'four': ((4,), 1, 0, False),
    'valid_ptr_result': ((1, 0, 4, STRING), OBJECT, 0, False),
    'str': ((STRING,), OBJECT, 0, False),
    'online': ((STRING,), OBJECT, 0, True),
    'muted_results': ((1,), 0, 1, False),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dll', type=Path)
    parser.add_argument('--usage', type=Path, default=OUT / 'missions/native-usage.tsv')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--only', action='append', default=[], help='table/id, both decimal')
    parser.add_argument('--allow-unofficial', action='store_true', help='generate from unverified game files; recorded in <output>.provenance.json')
    args = parser.parse_args()
    provenance = gate_or_exit(parser, args.dll.parent, (args.dll.name,), args.allow_unofficial, 'bvm_native_probe.py')
    with args.usage.open(encoding='utf-8', newline='') as source:
        rows = list(csv.DictReader(source, delimiter='\t'))
    model = Dispatcher(args.dll)
    counts = Counter()
    with args.output.open('x', encoding='utf-8', newline='\n') as target:
        for row in rows:
            table, number = int(row['native_table']), int(row['native_id'])
            if args.only and f'{table}/{number}' not in args.only:
                continue
            cases = {name: model.run(table, number, fixture) for name, fixture in FIXTURES.items()}
            counts[sum(case['delta'] is not None for case in cases.values())] += 1
            target.write(json.dumps({'edf_sha256': SHA256, 'table': table, 'id': number, 'cases': cases}) + '\n')
    write_provenance(args.output, provenance)
    print('IDs grouped by number of fixtures that reached the stack commit:', dict(sorted(counts.items())))


if __name__ == '__main__':
    main()
