"""Build and query a read-only, RVA-indexed snapshot of the installed EDF6 PE images."""

import argparse
from bisect import bisect_left, bisect_right
import csv
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys
import tempfile

import verify_install


from edf6re_lib.paths import out_root

ROOT = Path(__file__).resolve().parent
OUT = out_root()   # every generated artifact lives here: $EDF6RE_OUT or <repo>/out (git-ignored)
DEFAULT_DB = OUT / 'vanilla.sqlite'
MODULES = ('EDF.dll', 'EDF6.exe')
SCHEMA = '''
CREATE TABLE image(module TEXT PRIMARY KEY, sha256 TEXT, timestamp INTEGER,
    image_base INTEGER, entry_rva INTEGER, file_size INTEGER, image_size INTEGER) WITHOUT ROWID;
CREATE TABLE section(module TEXT, rva INTEGER, name TEXT, virtual_size INTEGER,
    raw_size INTEGER, file_offset INTEGER, executable INTEGER, PRIMARY KEY(module,rva)) WITHOUT ROWID;
CREATE TABLE unwind(module TEXT, begin_rva INTEGER, end_rva INTEGER, info_rva INTEGER,
    PRIMARY KEY(module,begin_rva,end_rva,info_rva)) WITHOUT ROWID;
CREATE TABLE instruction(module TEXT, rva INTEGER, bytes BLOB, mnemonic TEXT, operands TEXT,
    PRIMARY KEY(module,rva)) WITHOUT ROWID;
CREATE TABLE reference(module TEXT, source_rva INTEGER, target_rva INTEGER, kind TEXT,
    PRIMARY KEY(module,target_rva,source_rva,kind)) WITHOUT ROWID;
CREATE TABLE symbol(module TEXT, rva INTEGER, kind TEXT, name TEXT,
    PRIMARY KEY(module,rva,kind,name)) WITHOUT ROWID;
CREATE TABLE vtable(module TEXT, rva INTEGER, class_name TEXT, object_offset INTEGER, col_rva INTEGER,
    PRIMARY KEY(module,rva)) WITHOUT ROWID;
CREATE TABLE vslot(module TEXT, vtable_rva INTEGER, slot INTEGER, target_rva INTEGER,
    PRIMARY KEY(module,vtable_rva,slot)) WITHOUT ROWID;
CREATE TABLE note(rva INTEGER, path TEXT, line INTEGER, section TEXT, excerpt TEXT,
    PRIMARY KEY(rva,path,line)) WITHOUT ROWID;
'''

RIP = re.compile(r'\[rip(?: ([+-]) (0x[0-9a-f]+|[0-9]+))?\]')
ADDRESS = re.compile(r'(?<![\w+])0x[0-9a-f]{4,8}(?![\da-f])', re.I)
TYPE_NAME = re.compile(rb'\.\?A[UV][!-~]{1,400}?@@\0')


def executable_ranges(pe):
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            size = min(section.Misc_VirtualSize or section.SizeOfRawData, section.SizeOfRawData)
            start = section.VirtualAddress
            yield start, start + size


def symbols(pe):
    yield pe.OPTIONAL_HEADER.AddressOfEntryPoint, 'entry', 'PE entry point'
    for directory in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        for library in getattr(pe, directory, []):
            dll = library.dll.decode('ascii', errors='replace')
            for symbol in library.imports:
                name = symbol.name.decode('ascii', errors='replace') if symbol.name else f'#{symbol.ordinal}'
                yield symbol.address - pe.OPTIONAL_HEADER.ImageBase, 'iat', f'{dll}!{name}'
    exports = getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None)
    if exports:
        for symbol in exports.symbols:
            name = symbol.name.decode('ascii', errors='replace') if symbol.name else f'#{symbol.ordinal}'
            if symbol.forwarder:
                yield symbol.address, 'forwarder', f'{name} -> {symbol.forwarder.decode("ascii", errors="replace")}'
            else:
                yield symbol.address, 'export', name


def rtti(db, module, pe, mapped, ranges):
    """Locate MSVC x64 complete-object locators via relocated preferred-base pointers."""
    base = pe.OPTIONAL_HEADER.ImageBase
    types = {match.start() - 16: match[0][:-1].decode('ascii') for match in TYPE_NAME.finditer(mapped)}
    relocated = sorted({entry.rva for block in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', [])
                        for entry in block.entries if entry.type == 10 and entry.rva + 8 <= len(mapped)})
    pointers = {rva: struct.unpack_from('<Q', mapped, rva)[0] - base for rva in relocated}
    tables = []
    slots = []
    for location, target in pointers.items():
        if not 0 <= target <= len(mapped) - 24:
            continue
        signature, offset, _, type_rva, _, self_rva = struct.unpack_from('<6I', mapped, target)
        if signature != 1 or self_rva != target or type_rva not in types:
            continue
        first_slot = location + 8
        slot_rva = first_slot
        while any(start <= pointers.get(slot_rva, -1) < end for start, end in ranges):
            slots.append((module, first_slot, (slot_rva - first_slot) // 8, pointers[slot_rva]))
            slot_rva += 8
        if slot_rva > first_slot:
            tables.append((module, first_slot, types[type_rva], offset, target))
    db.executemany('INSERT INTO vtable VALUES (?,?,?,?,?)', tables)
    db.executemany('INSERT INTO vslot VALUES (?,?,?,?)', slots)


def references(rva, size, mnemonic, operands, image_size):
    if mnemonic.startswith(('j', 'loop')) or mnemonic == 'call':
        if operands.startswith('0x') and operands[2:].isalnum():
            target = int(operands, 16)
            if 0 <= target < image_size:
                yield target, 'call' if mnemonic == 'call' else 'branch'
    if '[rip' in operands:
        match = RIP.search(operands)
        if match:
            sign, magnitude = match.groups()
            displacement = int(magnitude, 0) if magnitude else 0
            target = rva + size + (-displacement if sign == '-' else displacement)
            if 0 <= target < image_size:
                yield target, 'rip'


def decode_image(db, module, pe, mapped, ranges, boundaries, capstone):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.skipdata = True
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    instructions = []
    edges = []
    for start, end in ranges:
        cuts = [start, *boundaries[bisect_right(boundaries, start):bisect_left(boundaries, end)], end]
        for left, right in zip(cuts, cuts[1:]):
            next_rva = left
            for rva, size, mnemonic, operands in decoder.disasm_lite(mapped[left:right], left):
                if rva != next_rva or rva + size > right:
                    raise ValueError(f'{module} decode coverage mismatch at {rva:#x}')
                instructions.append((module, rva, mapped[rva:rva + size], mnemonic, operands))
                edges.extend((module, rva, target, kind)
                             for target, kind in references(rva, size, mnemonic, operands, image_size))
                next_rva = rva + size
            while next_rva < right:
                byte = mapped[next_rva:next_rva + 1]
                instructions.append((module, next_rva, byte, '.byte', f'0x{byte[0]:02x}'))
                next_rva += 1
            if len(instructions) >= 30_000:
                db.executemany('INSERT INTO instruction VALUES (?,?,?,?,?)', instructions)
                db.executemany('INSERT INTO reference VALUES (?,?,?,?)', edges)
                instructions.clear()
                edges.clear()
        db.executemany('INSERT INTO instruction VALUES (?,?,?,?,?)', instructions)
        db.executemany('INSERT INTO reference VALUES (?,?,?,?)', edges)
        instructions.clear()
        edges.clear()


def add_image(db, path, capstone, pefile):
    module = path.name
    raw = path.read_bytes()
    pe = pefile.PE(data=raw, fast_load=True)
    if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20b:
        raise ValueError(f'{path} is not a Windows x64 PE')
    pe.parse_data_directories(directories=[0, 1, 3, 5, 13])
    header = pe.OPTIONAL_HEADER
    db.execute('INSERT INTO image VALUES (?,?,?,?,?,?,?)', (module, hashlib.sha256(raw).hexdigest(),
               pe.FILE_HEADER.TimeDateStamp, header.ImageBase, header.AddressOfEntryPoint,
               len(raw), header.SizeOfImage))
    db.executemany('INSERT INTO section VALUES (?,?,?,?,?,?,?)', [
        (module, s.VirtualAddress, s.Name.rstrip(b'\0').decode('ascii', errors='replace'),
         s.Misc_VirtualSize, s.SizeOfRawData, s.PointerToRawData, bool(s.Characteristics & 0x20000000))
        for s in pe.sections])
    unwind = sorted({(entry.struct.BeginAddress, entry.struct.EndAddress, entry.struct.UnwindData)
                     for entry in getattr(pe, 'DIRECTORY_ENTRY_EXCEPTION', [])})
    db.executemany('INSERT INTO unwind VALUES (?,?,?,?)', [(module, *item) for item in unwind])
    names = list(symbols(pe))
    db.executemany('INSERT OR IGNORE INTO symbol VALUES (?,?,?,?)', [(module, *item) for item in names])
    boundaries = {rva for begin, end, _ in unwind for rva in (begin, end)}
    boundaries.update(rva for rva, kind, _ in names if kind in ('entry', 'export'))
    ranges = list(executable_ranges(pe))
    mapped = pe.get_memory_mapped_image()
    if any(end > len(mapped) for _, end in ranges):
        raise ValueError(f'{module} has an executable range outside its mapped image')
    rtti(db, module, pe, mapped, ranges)
    decode_image(db, module, pe, mapped, ranges, sorted(boundaries), capstone)
    print(f'{module}: decoded {sum(end - start for start, end in ranges):,} executable bytes', flush=True)
    return pe.FILE_HEADER.TimeDateStamp, ranges


def add_notes(db, notes_dir, file_identity):
    # Only associate the project's hard-coded addresses with its documented Steam DLL build.
    stamp, ranges = file_identity
    if stamp != 0x678ccb46:
        return
    paths = sorted(notes_dir.rglob('*.md'))
    notes = []
    for path in paths:
        if not path.is_file():
            continue
        relative = path.relative_to(notes_dir).as_posix()
        heading = ''
        for number, line in enumerate(path.read_text(encoding='utf-8-sig').splitlines(), 1):
            if line.startswith('#'):
                heading = line.lstrip('# ').strip()
            candidates = {int(match[0], 16) for match in ADDRESS.finditer(line)}
            notes.extend((rva, relative, number, heading, line.strip()) for rva in sorted(candidates)
                         if any(begin <= rva < end for begin, end in ranges))
    db.executemany('INSERT INTO note VALUES (?,?,?,?,?)', notes)


def build(args):
    import capstone
    import pefile

    args.db.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='vanilla-build-', dir=args.db.parent) as staging:
        path = Path(staging) / args.db.name
        with sqlite3.connect(path) as db:
            db.execute('PRAGMA journal_mode=OFF')
            db.execute('PRAGMA synchronous=OFF')
            db.execute('PRAGMA temp_store=MEMORY')
            db.executescript(SCHEMA)
            for module in args.modules:
                identity = add_image(db, args.game / module, capstone, pefile)
                if module == MODULES[0] and args.notes_dir:
                    add_notes(db, args.notes_dir, identity)
            db.execute('CREATE INDEX reference_source ON reference(module,source_rva)')
            db.execute('CREATE INDEX note_source ON note(path,line)')
            db.execute('PRAGMA user_version=1')
            db.commit()
        db.close()
        path.replace(args.db)
    verify_install.write_provenance(args.db, args.provenance)   # -> <db>.provenance.json


def provenance_warnings(db, db_path):
    """Warnings when the database was built from files outside known-builds.tsv or marked unofficial."""
    hashes = dict(db.execute('SELECT module,sha256 FROM image'))
    return verify_install.provenance_warnings(verify_install.read_provenance(db_path), hashes)


def format_instruction(row):
    rva, code, mnemonic, operands = row
    return f'{rva:08X}  {code.hex(" ").upper():44}  {mnemonic:12} {operands}'.rstrip()


def bounds(db, module, rva):
    row = db.execute('''SELECT begin_rva,end_rva,info_rva FROM unwind
                       WHERE module=? AND begin_rva<=? AND end_rva>?
                       ORDER BY begin_rva DESC,end_rva LIMIT 1''', (module, rva, rva)).fetchone()
    return row


def show(db, args):
    record = bounds(db, args.module, args.rva)
    if record:
        start, end, info = record
        print(f'{args.module} .pdata [0x{start:08X}, 0x{end:08X})  unwind 0x{info:08X}')
    else:
        start, end = args.rva, args.rva + 0x100
        print(f'{args.module} 0x{start:08X}  (outside .pdata; linear decode)')
    if args.from_rva:
        row = db.execute('SELECT rva,length(bytes) FROM instruction WHERE module=? AND rva<=? ORDER BY rva DESC LIMIT 1',
                         (args.module, args.rva)).fetchone()
        start = row[0] if row and args.rva < row[0] + row[1] else args.rva
    rows = db.execute('SELECT rva,bytes,mnemonic,operands FROM instruction WHERE module=? AND rva>=? AND rva<? ORDER BY rva LIMIT ?',
                      (args.module, start, end, args.limit if args.limit is not None else -1))
    for row in rows:
        print(('> ' if row[0] <= args.rva < row[0] + len(row[1]) else '  ') + format_instruction(row))


def refs(db, args):
    outgoing = args.outgoing or args.function
    lhs, rhs = ('source_rva', 'target_rva') if outgoing else ('target_rva', 'source_rva')
    record = bounds(db, args.module, args.rva) if args.function else None
    start, end = record[:2] if record else (args.rva, args.rva + 1)
    # Column names are selected above from the fixed schema.
    rows = db.execute(f'''SELECT r.source_rva,r.target_rva,r.kind,i.mnemonic,i.operands
                          FROM reference r JOIN instruction i ON i.module=r.module AND i.rva=r.source_rva
                          WHERE r.module=? AND r.{lhs}>=? AND r.{lhs}<?
                          ORDER BY r.{lhs},r.{rhs} LIMIT ?''', (args.module, start, end, args.limit))
    for source, target, kind, mnemonic, operands in rows:
        print(f'0x{source:08X} -> 0x{target:08X}  {kind:6}  {mnemonic} {operands}')


def find(db, args):
    for rva, kind, name in db.execute('''SELECT rva,kind,name FROM symbol WHERE module=? AND instr(lower(name),lower(?))>0
        UNION ALL SELECT rva,'RTTI',class_name FROM vtable WHERE module=? AND instr(lower(class_name),lower(?))>0
        ORDER BY rva LIMIT ?''', (args.module, args.text, args.module, args.text, args.limit)):
        print(f'0x{rva:08X}  {kind:10} {name}')
    if args.module == MODULES[0]:
        directory = OUT / 'angelscript'
        identity = directory / 'sha256.txt'
        binary_hash = db.execute('SELECT sha256 FROM image WHERE module=?', (args.module,)).fetchone()[0]
        if identity.is_file() and identity.read_text(encoding='ascii').strip() == binary_hash:
            needle = args.text.casefold()
            with (directory / 'registrations.tsv').open(encoding='utf-8', newline='') as table:
                matches = [row for row in csv.DictReader(table, delimiter='\t')
                           if needle in f'{row["namespace"]} {row["owner"]} {row["declaration"]}'.casefold()]
            for row in matches[:args.limit] if args.limit >= 0 else matches:
                namespace = row['namespace']
                qualified = '::'.join(part for part in (namespace, row['owner'], row['declaration']) if part)
                address = row['implementation_rva'] or row['call_rva']
                print(f'{address}  AngelScript {row["kind"]}  {qualified}  [registration {row["call_rva"]}]')
        for path, line, section, excerpt in db.execute('''SELECT DISTINCT path,line,section,excerpt FROM note
                WHERE instr(excerpt,?)>0 OR instr(section,?)>0 ORDER BY path,line LIMIT ?''',
                (args.text, args.text, args.limit)):
            print(f'{path}:{line}  {section}\n    {excerpt}')


def notes(db, args):
    if args.module != MODULES[0]:
        raise ValueError('Project note candidates are indexed for EDF.dll only')
    record = bounds(db, args.module, args.rva) if args.function else None
    start, end = record[:2] if record else (args.rva, args.rva + 1)
    for rva, path, line, section, excerpt in db.execute('SELECT * FROM note WHERE rva>=? AND rva<? ORDER BY path,line,rva LIMIT ?',
                                                       (start, end, args.limit)):
        print(f'0x{rva:08X}  {path}:{line}  {section}\n    {excerpt}')


def vtable(db, args):
    metadata = db.execute('SELECT class_name,object_offset,col_rva FROM vtable WHERE module=? AND rva=?',
                          (args.module, args.rva)).fetchone()
    if metadata is None:
        raise ValueError(f'No RTTI vtable candidate at {args.rva:#x}')
    name, offset, col = metadata
    print(f'{name}  object offset {offset:#x}  complete-object locator {col:#x}')
    for slot, target in db.execute('SELECT slot,target_rva FROM vslot WHERE module=? AND vtable_rva=? ORDER BY slot',
                                   (args.module, args.rva)):
        print(f'{slot:4}  [0x{args.rva + slot * 8:08X}] -> 0x{target:08X}')


def index_rows(path):
    with path.open(encoding='utf-8', newline='') as stream:
        yield from csv.DictReader(stream, delimiter='\t')


def function(db, args):
    directory = OUT / 'function-index'
    manifest = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
    binary_hash = db.execute('SELECT sha256 FROM image WHERE module=?', (args.module,)).fetchone()[0]
    if manifest['images_sha256'][args.module] != binary_hash:
        raise ValueError('Function index and database have different binary hashes')
    rows = {row['rva']: row for row in index_rows(directory / 'functions.tsv') if row['module'] == args.module}
    is_rva = args.query.lower().startswith('0x') or re.fullmatch(r'(?=[0-9a-f]*[0-9])[0-9a-f]{1,8}', args.query, re.I)
    if is_rva:
        address = int(args.query, 16)
        key = f'0x{address:08X}'
        if key not in rows and (record := bounds(db, args.module, address)):
            begin = f'0x{record[0]:08X}'
            owner = next((item for item in index_rows(directory / 'unwind-ranges.tsv')
                          if item['module'] == args.module and item['begin_rva'] == begin), None)
            if owner and owner['owner_rva']:
                key = owner['owner_rva']
            elif owner:
                raise ValueError(f'{args.module} {begin} is indexed as {owner["classification"]}')
        if key not in rows:
            raise ValueError(f'No function-index entry at {args.module} {key}')
        aliases = [a for a in index_rows(directory / 'aliases.tsv') if a['module'] == args.module and a['rva'] == key]
        print_function_row(rows[key])
        for alias in aliases[:args.limit]:
            print(f'  {alias["evidence"]}  {alias["label"]}  ({alias["detail"]})')
    else:
        query = args.query.casefold()
        matches = {rva for rva,row in rows.items() if query in row['label'].casefold()}
        matches.update(a['rva'] for a in index_rows(directory / 'aliases.tsv')
                       if a['module'] == args.module and query in a['label'].casefold())
        if not matches:
            raise ValueError(f'No function-index name matches {args.query!r}')
        for rva in sorted(matches)[:args.limit]:
            print_function_row(rows[rva])


def print_function_row(row):
    location = row['artifact'] + (f':{row["line"]}' if row['line'] else '')
    print(f'{row["module"]} {row["rva"]}  {row["label"]}  [{row["label_kind"]}]')
    print(f'  VA {row["preferred_va"]}  file {row["file_offset"]}  {row["code_kind"]}  {location}')


def bvm_native(db, args):
    directory = OUT / 'bvm-native'
    metadata = json.loads((directory / 'summary.json').read_text(encoding='utf-8'))
    binary_hash = db.execute('SELECT sha256 FROM image WHERE module=?', (args.module,)).fetchone()[0]
    if args.module != MODULES[0] or metadata['edf_sha256'] != binary_hash:
        raise ValueError('BVM index applies to its matching EDF.dll image')
    key = str(args.table), str(args.native_id)
    found = next((row for row in index_rows(directory / 'signatures.tsv') if (row['table'],row['id']) == key), None)
    if found is None:
        raise ValueError(f'BVM native {args.table}/{args.native_id} does not occur in the indexed scripts')
    print(f'BVM {args.table}/{args.native_id}  params={found["indexed_param_types"] or "()"}'
          f'  returns={found["returns"]}  stack_delta={found["stack_delta"]}  script_sites={found["calls"]}')
    print(f'  dispatch bucket {found["dispatch_entry_rvas"]}  callsites {found["native_call_sites"] or "none"}')
    for row in index_rows(directory / 'arguments.tsv'):
        if (row['table'],row['id']) == key:
            print(f'  arg {row["arg"]} {row["indexed_type"]}  reads {row["read_rvas"] or "none in observed path"}')


def pseudocode(db, args):
    folders = [path / args.module for path in (args.pseudocode, args.unwind_pseudocode, args.retry_pseudocode,
               OUT / 'pseudocode-candidates', OUT / 'pseudocode-manual', OUT / 'pseudocode-angelscript',
               OUT / 'pseudocode-pointers', OUT / 'pseudocode-pointers-extra')]
    entries = {}
    for folder in folders:
        index_path = folder / 'functions.tsv'
        if index_path.exists():
            with index_path.open(encoding='utf-8', newline='') as index:
                for row in csv.DictReader(index, delimiter='\t'):
                    if row['status'] not in ('ok', 'failed'):
                        continue
                    address = int(row['rva'], 16)
                    existing = entries.get(address)
                    if existing is None or existing[1]['status'] == 'failed':
                        entries[address] = (folder, row)
    record = bounds(db, args.module, args.rva)
    start = record[0] if record else args.rva
    selected = entries.get(args.rva) or entries.get(start)
    skipped = folders[1] / 'unwind-unresolved.tsv'
    if selected is None and skipped.exists():
        with skipped.open(encoding='utf-8', newline='') as index:
            for row in csv.DictReader(index, delimiter='\t'):
                if int(row['begin_rva'], 16) == start and row['reason'].startswith('inside function '):
                    selected = entries.get(int(row['reason'].split()[-1], 16))
                    break
    if selected is None:
        raise ValueError(f'No C pseudocode indexed at {args.rva:#x}. Use show to read the assembly.')
    folder, entry = selected
    if entry['status'] != 'ok':
        detail = {'0x001E31F0': 'angelscript/registrations.pcode', '0x011E7E20': 'angelscript/handlers.pcode'}
        listing = detail.get(entry['rva']) if args.module == MODULES[0] else None
        hint = f' See {listing} for the instruction-level P-code and annotated assembly.' if listing else ''
        raise ValueError(f'{entry["rva"]} could not be decompiled: {entry["diagnostic"]}.{hint}')
    first_line = int(entry['line'])
    with (folder / entry['file']).open(encoding='utf-8') as source:
        for number, line in enumerate(source, 1):
            if number > first_line and line.startswith('/* RVA 0x'):
                break
            if number >= first_line:
                print(line, end='')


def summary(db, args):
    names = ('module', 'sha256', 'timestamp', 'image_base', 'entry_rva', 'file_size', 'image_size')
    images = []
    for row in db.execute('SELECT * FROM image ORDER BY module'):
        module = row[0]
        info = dict(zip(names, row))
        for key in ('timestamp', 'image_base', 'entry_rva', 'image_size'):
            info[key] = f'0x{info[key]:X}'
        info['executable_bytes'], info['instruction_rows'], info['byte_rows'] = db.execute('''
            SELECT sum(length(bytes)),count(*),sum(mnemonic='.byte') FROM instruction WHERE module=?''', (module,)).fetchone()
        for key in ('unwind', 'reference', 'symbol', 'vtable', 'vslot'):
            info[key] = db.execute(f'SELECT count(*) FROM {key} WHERE module=?', (module,)).fetchone()[0]
        images.append(info)
    note_count, note_files = db.execute('SELECT count(*),count(DISTINCT path) FROM note').fetchone()
    print(json.dumps({'images': images, 'note_mentions': note_count, 'notes_with_mentions': note_files}, indent=2))


def verify(db, args):
    integrity = db.execute('PRAGMA integrity_check').fetchall()
    if integrity != [('ok',)]:
        raise ValueError(f'SQLite integrity_check failed: {integrity}')
    for module, expected_hash in db.execute('SELECT module,sha256 FROM image ORDER BY module'):
        raw = (args.game / module).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ValueError(f'{module} SHA-256 mismatch')
        sections = db.execute('''SELECT rva,virtual_size,raw_size,file_offset FROM section
                              WHERE module=? AND executable=1 ORDER BY rva''', (module,))
        verified_rows = verified_bytes = 0
        for start, virtual_size, raw_size, file_offset in sections:
            end = start + min(virtual_size or raw_size, raw_size)
            expected_rva = start
            for rva, code in db.execute('SELECT rva,bytes FROM instruction WHERE module=? AND rva>=? AND rva<? ORDER BY rva',
                                        (module, start, end)):
                offset = file_offset + rva - start
                if rva != expected_rva or not code or code != raw[offset:offset + len(code)]:
                    raise ValueError(f'{module}: gap, overlap or byte mismatch at {rva:#x}, expected {expected_rva:#x}')
                expected_rva += len(code)
                verified_rows += 1
                verified_bytes += len(code)
            if expected_rva != end:
                raise ValueError(f'{module}: expected executable section end {end:#x}, got {expected_rva:#x}')
        print(f'{module}: SHA-256 and {verified_bytes:,} executable bytes / {verified_rows:,} rows verified')


def assembly(db, args):
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        for warning in args.provenance_warnings:
            output.write(f'; WARNING: not a known official build: {warning}\n')
        output.write(f'; {args.module}  SHA-256 {db.execute("SELECT sha256 FROM image WHERE module=?", (args.module,)).fetchone()[0]}\n')
        starts = dict(db.execute('SELECT begin_rva,end_rva FROM unwind WHERE module=? ORDER BY end_rva DESC', (args.module,)))
        for row in db.execute('SELECT rva,bytes,mnemonic,operands FROM instruction WHERE module=? ORDER BY rva', (args.module,)):
            if row[0] in starts:
                output.write(f'\n; .pdata 0x{row[0]:08X} .. 0x{starts[row[0]]:08X} exclusive\n')
            output.write(format_instruction(row) + '\n')


def module_list(text):
    names = [name.strip() for name in text.split(',') if name.strip()]
    unknown = sorted(set(names) - set(MODULES))
    if unknown or not names:
        raise argparse.ArgumentTypeError(f'expected a comma-separated subset of {",".join(MODULES)}')
    return [module for module in MODULES if module in names]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, default=DEFAULT_DB)
    parser.add_argument('--module', choices=MODULES, default=MODULES[0])
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('build', help='rebuild the database from the original PE files')
    command.add_argument('game', type=Path)
    command.add_argument('--allow-unofficial', action='store_true',
                         help='build from unverified game files; recorded in <db>.provenance.json')
    command.add_argument('--notes-dir', type=Path, default=None,
                         help='optional directory of Markdown notes whose RVA mentions are indexed (skipped when omitted)')
    command.add_argument('--modules', type=module_list,
                         default=list(MODULES), help='comma-separated subset of EDF.dll,EDF6.exe (default: both)')
    commands.add_parser('summary', help='print binary identities and coverage')
    command = commands.add_parser('verify', help='check hashes, SQLite integrity and every executable byte')
    command.add_argument('game', type=Path)
    command.add_argument('--allow-unofficial', action='store_true', help='verify against unverified game files')
    command = commands.add_parser('asm', help='export readable assembly for the selected image')
    command.add_argument('output', type=Path)
    command = commands.add_parser('function', help='look up a function by name or hexadecimal RVA')
    command.add_argument('query')
    command.add_argument('--limit', type=int, default=12, help='maximum names or aliases to print')
    command = commands.add_parser('bvm', help='look up a stock BVM native by table and decimal ID')
    command.add_argument('table', type=int, choices=range(4))
    command.add_argument('native_id', type=int)
    for name, handler in [('show', show), ('refs', refs), ('notes', notes), ('vtable', vtable),
                          ('find', find), ('c', pseudocode)]:
        command = commands.add_parser(name)
        if name == 'find':
            command.add_argument('text')
        else:
            command.add_argument('rva', type=lambda value: int(value, 16))
        if name in ('show', 'refs', 'notes', 'find'):
            command.add_argument('--limit', type=int, default=None if name == 'show' else 40)
        if name == 'show':
            command.add_argument('--from-rva', action='store_true')
        if name == 'refs':
            orientation = command.add_mutually_exclusive_group()
            orientation.add_argument('--outgoing', action='store_true')
            orientation.add_argument('--function', action='store_true')
        if name == 'notes':
            command.add_argument('--function', action='store_true')
        if name == 'c':
            command.add_argument('--pseudocode', type=Path, default=OUT / 'pseudocode')
            command.add_argument('--unwind-pseudocode', type=Path, default=OUT / 'pseudocode-unwind')
            command.add_argument('--retry-pseudocode', type=Path, default=OUT / 'pseudocode-retry')
        command.set_defaults(handler=handler)
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    try:
        if args.command in ('build', 'verify'):
            gated = args.modules if args.command == 'build' else MODULES
            args.provenance = verify_install.gate_or_exit(parser, args.game, gated, args.allow_unofficial,
                                                          f'vanilla.py {args.command}')
        if args.command == 'build':
            build(args)
        else:
            db = sqlite3.connect(args.db.resolve().as_uri() + '?mode=ro', uri=True)
            try:
                args.provenance_warnings = provenance_warnings(db, args.db)
                verify_install.print_provenance_warnings(args.provenance_warnings)
                handlers = {'summary': summary, 'asm': assembly, 'verify': verify, 'function': function, 'bvm': bvm_native}
                handler = handlers.get(args.command) or args.handler
                handler(db, args)
            finally:
                db.close()
    except (OSError, ValueError, sqlite3.Error, ImportError) as exc:
        parser.exit(1, f'{exc}\n')


if __name__ == '__main__':
    main()
