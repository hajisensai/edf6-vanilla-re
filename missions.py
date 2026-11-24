"""Export local stock EDF6 mission code without loading Mods or running the game."""

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import struct
import sys

from verify_install import gate_or_exit, write_provenance


from edf6re_lib.paths import out_root

ROOT = Path(__file__).resolve().parent
OUT = out_root()   # every generated artifact lives here: $EDF6RE_OUT or <repo>/out (git-ignored)
ARCHIVES = ('Root.cpk', 'Chunk01.cpk', 'Chunk02.cpk', 'DX11.cpk')
EXTENSIONS = {'.AC', '.H', '.BVM'}
NAMES = {
    0x01: 'storei', 0x02: 'pop', 0x09: 'neg', 0x14: 'pushg', 0x15: 'push',
    0x16: 'storeg', 0x17: 'pushl', 0x18: 'pushla', 0x19: 'storel', 0x1a: 'pushs',
    0x1b: 'fp+', 0x1c: 'fp-', 0x1d: 'and', 0x26: 'jz', 0x28: 'jmp', 0x29: 'call',
    0x2a: 'ret', 0x30: 'end', 0x33: 'push1', 0x34: 'jne', 0x36: 'storeind',
}
INCLUDE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.M)


def bvm_listing(data, vm, natives=None):
    """Return (listing, functions, instructions); append (table, id, line, offset) per native call to natives."""
    program = vm.parse(data)
    header = struct.unpack_from('<20I', data)
    code = vm._decode(data, header[12], header[14])
    functions = [(f.name, f.code, f.entry, f.types.hex(' '), f.signature_flags) for f in program.funcs]
    groups = [('<init>', program.init, 0, '', 0), *functions]
    labels = {}
    position = 0
    for name, instructions, entry, _, _ in groups:
        if instructions:
            labels[code[position + entry][0]] = name
        position += len(instructions)

    native_sites = []

    def lines():
        yield f'; {program.name} | {len(functions)} functions | addresses are BVM file offsets'
        for slot, name in enumerate(program.globals):
            yield f'; global[{slot}] {name}'
        position = 0
        for name, instructions, entry, types, flags in groups:
            if not instructions:
                continue
            yield f'\n; {name} entry=0x{code[position + entry][0]:08X} types=[{types}] flags={flags:#x}'
            for instruction in instructions:
                if code[position][1] in vm.OP_NATIVE:
                    native_sites.append(code[position])
                yield bvm_instruction(data, vm, code[position], instruction, program, labels)
                position += 1
        if position < len(code):
            yield '\n; Function table entry stubs'
            for row in code[position:]:
                yield bvm_instruction(data, vm, row, None, program, labels)

    text = '\n'.join(lines()) + '\n'
    if natives is not None:
        # 1-based line numbers in the written listing, found by the instruction's own offset column.
        wanted = {f'{offset:08X}  ': (op, value, offset) for offset, op, _, value, _ in native_sites}
        for number, line in enumerate(text.splitlines(), 1):
            if (site := wanted.get(line[:10])) is not None:
                op, value, offset = site
                natives.append((op - vm.OP_NAT0, value, number, offset))
    return text, len(functions), len(code)


def bvm_instruction(data, vm, row, instruction, program, labels):
    offset, op, width, value, kind = row
    raw = data[offset:offset + 1 + width + int(kind is not None)]
    name = NAMES.get(op, f'op_{op:02x}')
    annotation = ''
    if op in vm.JUMPS or op == vm.OP_CALL:
        target = offset + value
        annotation = f' -> 0x{target:08X} {labels.get(target, "")}'
    elif op == vm.OP_PUSHS:
        annotation = ' ' + json.dumps(instruction.v, ensure_ascii=False)
    elif op in (vm.OP_PUSHG, vm.OP_STOREG) and value < len(program.globals):
        annotation = f' {program.globals[value]}'
    elif op in vm.OP_NATIVE:
        name = f'native[{op - vm.OP_NAT0}]'
        signature = vm.SIG6.get((op, value))
        annotation = f'  signature={signature}' if signature else '  signature=unknown'
    raw_operand = str(value) if width or op in vm.OPERAND else ''
    type_byte = f' type=0x{kind:02X}' if kind is not None else ''
    return f'{offset:08X}  {raw.hex(" ").upper():17}  {name:12} {raw_operand}{type_byte}{annotation}'.rstrip()


def write_native_usage(path, usage, vm):
    """One row per (native table, id): call sites, scripts, the SIG6/NET6 entry if any, and the first call site."""
    with path.open('x', encoding='utf-8', newline='') as file:
        writer = csv.writer(file, delimiter='\t', lineterminator='\n')
        writer.writerow(('native_table', 'native_id', 'call_sites', 'script_count', 'signature_known', 'param_types',
                         'return_count', 'stack_delta_from_NET6', 'example_path', 'example_line', 'example_file_offset'))
        for (table, number), (sites, scripts, (example, line, offset)) in sorted(usage.items()):
            key = vm.OP_NAT0 + table, number
            signature = vm.SIG6.get(key)
            delta = vm.NET6.get(key)
            writer.writerow((table, number, sites, len(scripts), int(signature is not None),
                             signature[0] if signature else '', signature[1] if signature else '',
                             '' if delta is None else delta, example, line, f'0x{offset:08X}'))


def archive_member(directory, name):
    member = PureWindowsPath(directory) / name
    if member.is_absolute() or member.drive or ':' in str(member) or '..' in member.parts:
        raise ValueError(f'invalid archive member {member}')
    return Path(*member.parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('game', type=Path)
    parser.add_argument('--output', type=Path, default=OUT / 'missions')
    parser.add_argument('--allow-unofficial', action='store_true', help='generate from unverified game files; recorded in provenance.json')
    args = parser.parse_args()
    from edf6re_lib import bvm41, rootcpk

    provenance = gate_or_exit(parser, args.game, ARCHIVES, args.allow_unofficial, 'missions.py')
    args.output.mkdir(parents=True, exist_ok=False)
    write_provenance(args.output, provenance)
    counts = Counter()
    usage = {}
    errors = 0
    with (args.output / 'files.tsv').open('x', encoding='utf-8', newline='') as file:
        index = csv.writer(file, delimiter='\t', lineterminator='\n')
        index.writerow(('archive', 'source', 'format', 'source_sha256', 'output', 'lines',
                        'functions', 'instructions', 'includes', 'error'))
        for archive in ARCHIVES:
            game = rootcpk.Game(str(args.game), archive)
            for directory, name in sorted(game.cpk.index):
                if directory.upper().split('/')[0] != 'MISSION' or Path(name).suffix.upper() not in EXTENSIONS:
                    continue
                member = archive_member(directory, name)
                extension = member.suffix.upper()
                output = Path(archive) / member
                if extension == '.BVM':
                    output = output.with_suffix('.BVM.asm')
                digest = ''
                try:
                    data = game.read(directory, name)
                    digest = hashlib.sha256(data).hexdigest()
                    functions = instructions = ''
                    includes = []
                    sites = []
                    if extension == '.BVM':
                        content, functions, instructions = bvm_listing(data, bvm41, sites)
                    else:
                        content = data.decode('utf-8-sig').replace('\r\n', '\n').replace('\r', '\n')
                        includes = INCLUDE.findall(content)
                    destination = args.output / output
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with destination.open('x', encoding='utf-8', newline='\n') as source:
                        source.write(content)
                except (OSError, ValueError, IndexError, KeyError, struct.error) as exc:
                    index.writerow((archive, member.as_posix(), extension, digest, '', '', '', '', '', str(exc)))
                    errors += 1
                    continue
                counts[archive, extension] += 1
                for table, number, line, offset in sites:
                    entry = usage.setdefault((table, number), [0, set(), (output.as_posix(), line, offset)])
                    entry[0] += 1
                    entry[1].add(output.as_posix())
                index.writerow((archive, member.as_posix(), extension, digest, output.as_posix(), len(content.splitlines()),
                                functions, instructions, json.dumps(includes, ensure_ascii=False), ''))
    write_native_usage(args.output / 'native-usage.tsv', usage, bvm41)
    for (archive, extension), count in sorted(counts.items()):
        print(f'{archive} {extension}: {count}')
    print(f'Errors: {errors}')
    return int(errors > 0)


if __name__ == '__main__':
    sys.exit(main())
