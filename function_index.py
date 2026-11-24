"""Merge the stock PE address, name, P-code, C, RTTI and unwind inventories."""

import argparse
from collections import Counter, defaultdict
import csv
import ctypes
import json
from pathlib import Path
import re
import sqlite3


from edf6re_lib.paths import out_root

ROOT = Path(__file__).resolve().parent
OUT = out_root()   # every generated artifact lives here: $EDF6RE_OUT or <repo>/out (git-ignored)
PSEUDOCODE_FOLDERS = ('pseudocode', 'pseudocode-unwind', 'pseudocode-retry', 'pseudocode-candidates',
                      'pseudocode-manual', 'pseudocode-angelscript', 'pseudocode-pointers', 'pseudocode-pointers-extra')
GENERATED = re.compile(r'(?:thunk_)?FUN_[0-9a-fA-F]+|sub_[0-9a-fA-F]+')
ORDER = {'shared_confirmed': -3, 'shared_likely': -2, 'shared_guess': -1, 'export': 0, 'pe_entry': 1, 'upstream_match': 2, 'script_binding': 3,
         'reverse_engineered_label': 4, 'ghidra_label': 5, 'rtti_slot_label': 6}
ANNOTATED = {
    0x1E31F0: 'angelscript/registrations.pcode',
    0x11E7E20: 'angelscript/handlers.pcode',
}
INLINE_TABLES = {0xB07DAC, 0xB0B56C, 0xB11918, 0x11EC44C, 0x1218014, 0x12A647C, 0x130C6B0}
FIELD = r'\[rcx(?: [+-] 0x[0-9a-f]+)?\]'
FIELD_LOAD = re.compile(rf'(?:rax|eax|xmm0), (?:byte|word|dword|qword) ptr ({FIELD})')
FIELD_ADDRESS = re.compile(rf'rax, ({FIELD})')
FIELD_STORE = re.compile(rf'(?:byte|word|dword|qword) ptr ({FIELD}), (?:rdx|edx|dx|dl|xmm1|0x[0-9a-f]+|[0-9]+)')
INTEGER_RETURN = re.compile(r'(?:rax|eax|al), (0x[0-9a-f]+|[0-9]+)')
ADJUST_THIS = re.compile(r'rcx, (-?0x[0-9a-f]+|[0-9]+)')


def hx(value, width=8):
    return '' if value is None else f'0x{value:0{width}X}'


def read_tsv(path):
    with path.open(encoding='utf-8', newline='') as source:
        yield from csv.DictReader(source, delimiter='\t')


def write_tsv(path, header, rows):
    with path.open('x', encoding='utf-8', newline='') as target:
        writer = csv.writer(target, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def decompiler_entries(modules=('EDF.dll', 'EDF6.exe')):
    records = {}
    for folder in PSEUDOCODE_FOLDERS:
        for index in sorted((OUT / folder).glob('*/functions.tsv')):
            module = index.parent.name
            if module not in modules:
                continue
            for row in read_tsv(index):
                address = int(row['rva'], 16)
                key = module, address
                if row['status'] == 'ok':
                    status = 'manual_c' if folder == 'pseudocode-manual' else 'ghidra_c'
                    artifact = f'{folder}/{module}/{row["file"]}'
                    records[key] = (status, row['name'], artifact, int(row['line']))
                else:
                    records.setdefault(key, ('assembly', row['name'], f'assembly/{module}.asm', None))
    for rva, path in ANNOTATED.items() if 'EDF.dll' in modules else ():
        key = 'EDF.dll', rva
        name = records.get(key, ('', f'FUN_{0x180000000 + rva:x}', '', None))[1]
        with (OUT / path).open(encoding='utf-8') as artifact:
            line = next((i for i, text in enumerate(artifact, 1) if text.startswith(f'{rva:08X}  ')), None)
        if line is None:
            raise ValueError(f'Missing P-code entry marker: {path}, RVA {rva:#x}')
        records[key] = ('raw_pcode', name, path, line)
    return records


def rtti_demangler():
    try:
        api = ctypes.windll.dbghelp.UnDecorateSymbolName
    except (AttributeError, OSError):
        return lambda raw: raw
    api.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32]
    api.restype = ctypes.c_uint32
    cache = {}
    suffix = "::`vftable'"

    def decoded(raw):
        if raw not in cache:
            # Translate a type descriptor name into a synthetic MSVC vftable decoration.
            decorated = '??_7' + raw[4:] + '6B@'
            buffer = ctypes.create_string_buffer(4096)
            result = api(decorated.encode('ascii'), buffer, len(buffer), 0x1000)
            name = buffer.value.decode('ascii', errors='replace').removesuffix(suffix) if result else raw
            cache[raw] = raw if name == decorated else name
        return cache[raw]

    return decoded


def shared_function_labels(db):
    """Yield (module, row) from shared/functions for the build whose sha256 matches the indexed image."""
    shared = ROOT / 'shared'
    builds = shared / 'builds.tsv'
    if not builds.exists():
        return
    hashes = dict(db.execute('SELECT module,sha256 FROM image'))
    with builds.open(encoding='utf-8', newline='') as stream:
        lines = [line for line in stream if line.strip() and not line.startswith('#')]
    for build in csv.DictReader(lines, delimiter='\t'):
        module = build['module']
        table = shared / 'functions' / f'{module}.tsv'
        if hashes.get(module) != build['sha256'] or not table.exists():
            continue
        with table.open(encoding='utf-8', newline='') as stream:
            rows = [line for line in stream if line.strip() and not line.startswith('#')]
        for row in csv.DictReader(rows, delimiter='\t'):
            if row['build'] == build['build']:
                yield module, row


def aliases_for(db, records):
    aliases = defaultdict(set)

    def add(key, source, label, detail):
        if key in records:
            aliases[key].add((source, label, detail))

    for module, rva, kind, name in db.execute("SELECT * FROM symbol WHERE kind IN ('entry','export')"):
        add((module, rva), 'pe_entry' if kind == 'entry' else 'export', name, 'PE header' if kind == 'entry' else 'PE export directory')
    for module, row in shared_function_labels(db):
        add((module, int(row['rva'], 16)), f'shared_{row["confidence"]}', row['name'], row['evidence'])
    for row in read_tsv(ROOT / 'function-labels.tsv'):
        add((row['module'], int(row['rva'], 16)), row['evidence'], row['label'], row['source'])
    indexed = {module for module, in db.execute('SELECT module FROM image')}
    registrations = read_tsv(OUT / 'angelscript/registrations.tsv') if 'EDF.dll' in indexed else ()
    for row in registrations:
        if not row['implementation_rva']:
            continue
        name = '::'.join(part for part in (row['namespace'], row['owner'], row['declaration']) if part)
        if row['kind'] == 'object_behaviour':
            name += f' [behaviour {row["value"]}]'
        add(('EDF.dll', int(row['implementation_rva'], 16)), 'script_binding', name,
            f'AngelScript registration {row["call_rva"]}')
    for key, (_, name, _, _) in records.items():
        if name and not GENERATED.fullmatch(name) and not name.startswith(('read_berserker_', 'berserker_slot_',
                                                                            'copy_chat_lambda', 'ui_slot_')):
            add(key, 'ghidra_label', name, 'Ghidra program symbol')
    demangle = rtti_demangler()
    query = '''SELECT v.module,s.target_rva,v.class_name,v.object_offset,s.vtable_rva,s.slot
               FROM vslot s JOIN vtable v ON v.module=s.module AND v.rva=s.vtable_rva'''
    for module, target, cls, offset, vtable, slot in db.execute(query):
        name = f'{demangle(cls)}::vslot_{slot}'
        if offset:
            name += f' [this+{offset:#x}]'
        add((module, target), 'rtti_slot_label', name,
            f'vtable {hx(vtable)}, slot {slot}, subobject offset {offset:#x}, RTTI {cls}')
    return aliases


def runtime_ranges(db, records):
    owner = {}
    for path in sorted((OUT / 'pseudocode-unwind').glob('*/unwind-unresolved.tsv')):
        for row in read_tsv(path):
            if row['reason'].startswith('inside function '):
                owner[path.parent.name, int(row['begin_rva'], 16)] = int(row['reason'].split()[-1], 16)
    result = []
    for module, start, end, info in db.execute('SELECT * FROM unwind ORDER BY module,begin_rva,end_rva'):
        key = module, start
        if key in records:
            status, root = 'exact_entry', start
        elif module == 'EDF.dll' and start in INLINE_TABLES:
            status, root = 'inline_jump_table', None
        elif (module, start) in owner and (module, owner[module, start]) in records:
            status, root = 'owned_range', owner[module, start]
        else:
            status, root = 'unmatched_range', None
        result.append((module, hx(start), hx(end), hx(info), status, hx(root)))
    return result


def recognizable_body(db, module, rva, primary_names):
    rows = list(db.execute('SELECT rva,length(bytes),mnemonic,operands FROM instruction WHERE module=? AND rva>=? '
                           'ORDER BY rva LIMIT 2', (module, rva)))
    if not rows or rows[0][0] != rva:
        return None
    _, size, first, op = rows[0]
    if first == 'ret':
        return 'ImmediateReturn', 'entry ret'
    other = rows[1] if len(rows) > 1 and rows[1][0] == rva + size else None
    if first == 'jmp' or (other and first in ('add', 'sub') and ADJUST_THIS.fullmatch(op) and other[2] == 'jmp'):
        target = op if first == 'jmp' else other[3]
        delta = '' if first == 'jmp' else f'{first} {op}; '
        if re.fullmatch(r'0x[0-9a-f]+', target):
            called = (module, int(target, 16))
            if called in primary_names:
                return f'TailJump_{target}', f'{delta}jmp {target}, {primary_names[called]}'
    if other is None or other[2] != 'ret':
        return None
    if first == 'xor' and op in ('eax, eax', 'rax, rax'):
        return 'ReturnZero', f'{first} {op}; ret'
    if first == 'mov' and (match := INTEGER_RETURN.fullmatch(op)):
        return f'ReturnConstant_{match[1]}', f'{first} {op}; ret'
    if first in ('mov', 'movss', 'movsd', 'movzx', 'movsxd', 'movsx') and FIELD_LOAD.fullmatch(op):
        return 'ReadObjectField', f'{first} {op}; ret'
    if first == 'lea' and FIELD_ADDRESS.fullmatch(op):
        return 'ReturnObjectFieldAddress', f'{first} {op}; ret'
    if first in ('mov', 'movss', 'movsd') and FIELD_STORE.fullmatch(op):
        return 'WriteObjectField', f'{first} {op}; ret'
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    db = sqlite3.connect((OUT / 'vanilla.sqlite').as_uri() + '?mode=ro', uri=True)
    records = decompiler_entries(dict(db.execute('SELECT module,sha256 FROM image')))
    aliases = aliases_for(db, records)
    primary_names = {key: min(items, key=lambda item: (ORDER[item[0]], item[1], item[2]))[1]
                     for key, items in aliases.items() if items}
    primary_names.update((key, selected[1]) for key, selected in records.items() if key not in primary_names)
    ranges = runtime_ranges(db, records)
    images = dict(db.execute('SELECT module,image_base FROM image'))
    hashes = dict(db.execute('SELECT module,sha256 FROM image'))
    sections = defaultdict(list)
    for module, rva, name, virtual_size, raw_size, file_offset, executable in db.execute('SELECT * FROM section'):
        if executable:
            sections[module].append((rva, rva + min(virtual_size, raw_size), file_offset, name))
    exact = {(module, int(start, 16)): (end, info) for module, start, end, info, state, _ in ranges if state == 'exact_entry'}
    names = Counter()
    output_rows = []
    alias_rows = []
    for (module, rva), (code_kind, ghidra, artifact, line) in sorted(records.items()):
        section = next((s for s in sections[module] if s[0] <= rva < s[1]), None)
        if section is None:
            raise ValueError(f'Entry outside executable file bytes: {module} {rva:#x}')
        rows = sorted(aliases[module, rva], key=lambda item: (ORDER[item[0]], item[1], item[2]))
        if rows:
            best_kind, best_name, best_source = rows[0]
        elif pattern := recognizable_body(db, module, rva, primary_names):
            best_kind, best_name, best_source = 'instruction_pattern', f'{pattern[0]}_{rva:08X}', pattern[1]
        else:
            best_kind, best_name, best_source = 'address_label', ghidra, 'RVA-derived label'
        names[best_kind] += 1
        end, unwind_info = exact.get((module, rva), ('', ''))
        output_rows.append((module, hx(rva), hx(images[module] + rva, 16), hx(section[2] + rva - section[0]),
                            section[3], best_name, best_kind, best_source, ghidra, code_kind, artifact, line,
                            end, unwind_info, len(rows)))
        alias_rows.extend((module, hx(rva), label, kind, detail) for kind, label, detail in rows)
    args.output.mkdir(parents=True, exist_ok=False)
    write_tsv(args.output / 'functions.tsv', ('module','rva','preferred_va','file_offset','section','label','label_kind',
        'label_source','ghidra_label','code_kind','artifact','line','unwind_end_rva','unwind_info_rva','alias_count'), output_rows)
    write_tsv(args.output / 'aliases.tsv', ('module','rva','label','evidence','detail'), alias_rows)
    write_tsv(args.output / 'unwind-ranges.tsv', ('module','begin_rva','end_rva','info_rva','classification','owner_rva'), ranges)
    summary = {'images_sha256': hashes, 'unique_entries': len(records), 'names_by_evidence': dict(names),
               'aliases': len(alias_rows), 'code_kinds': dict(Counter(row[9] for row in output_rows)),
               'unwind_ranges': dict(Counter(row[4] for row in ranges))}
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
