"""Address lists that seed the later Ghidra passes, computed from vanilla.sqlite and earlier exports.

Each pass only gets addresses no earlier pass has exported or tried:

- retry:       entries whose C export failed in every earlier pass (usually per-function timeouts).
- candidates:  targets of direct `call` instructions and RTTI vtable slots.
- angelscript: native implementations recovered from the AngelScript registration table.
- pointers:    code addresses held in DIR64 base-relocated pointers or loaded with `lea reg, [rip+...]`.
               Targets that are 16-byte aligned right after an INT3 (0xCC) pad go first (pointers),
               the rest second (pointers-extra).

"Known" = every RVA listed in an earlier functions.tsv (ok or failed) plus every address list
already handed to Ghidra, so entries Ghidra could not turn into functions are not retried forever.
"""

import csv
from pathlib import Path
import struct

# Pseudocode folders in pass order; the function index reads the same names.
PASSES = ('pseudocode', 'pseudocode-unwind', 'pseudocode-retry', 'pseudocode-candidates',
          'pseudocode-angelscript', 'pseudocode-pointers', 'pseudocode-pointers-extra')
# Address lists (under <out>/addresses/<module>/) in the order they are handed to Ghidra.
LISTS = ('retry.txt', 'candidates.txt', 'angelscript.txt', 'pointers.txt', 'pointers-extra.txt')


def read_tsv(path):
    with Path(path).open(encoding='utf-8', newline='') as stream:
        yield from csv.DictReader(stream, delimiter='\t')


def exported_status(out, module, folders=PASSES):
    """{rva: True if some pass produced C, else False} over the functions.tsv files that exist."""
    status = {}
    for folder in folders:
        index = Path(out) / folder / module / 'functions.tsv'
        if index.exists():
            for row in read_tsv(index):
                rva = int(row['rva'], 16)
                status[rva] = status.get(rva, False) or row['status'] == 'ok'
    return status


def read_list(path):
    path = Path(path)
    if not path.exists():
        return set()
    return {int(line.strip(), 16) for line in path.read_text(encoding='ascii').splitlines() if line.strip()}


def known_entries(out, module, folders=PASSES, lists=LISTS):
    known = set(exported_status(out, module, folders))
    for name in lists:
        known |= read_list(Path(out) / 'addresses' / module / name)
    return known


def known_before(out, module, folder):
    """Entries known before the pass that writes `folder`; that pass's own and later outputs are ignored,
    so recomputing a list after a partial run gives the same answer."""
    earlier = PASSES[:PASSES.index(folder)]
    lists = [name for name, owner in zip(LISTS, PASSES[2:]) if owner in earlier]
    return known_entries(out, module, earlier, lists)


def executable_ranges(db, module):
    return [(rva, rva + min(virtual or raw, raw)) for rva, virtual, raw in db.execute(
        'SELECT rva,virtual_size,raw_size FROM section WHERE module=? AND executable=1 ORDER BY rva', (module,))]


def in_ranges(ranges, rva):
    return any(start <= rva < end for start, end in ranges)


def retry_rvas(out, module, folders=('pseudocode', 'pseudocode-unwind')):
    """Main-export failures that no listed pass turned into C. The retry pass reopens the saved project, which
    holds only the functions of the main analysis, so unwind-seeded failures cannot be retried there."""
    status = exported_status(out, module, folders)
    main = exported_status(out, module, folders[:1])
    return sorted(rva for rva in main if not status[rva])


def candidate_rows(db, module, known):
    """[(rva, direct_call_refs, rtti_slot_refs)] for call / vtable-slot targets in executable bytes."""
    ranges = executable_ranges(db, module)
    calls = dict(db.execute("SELECT target_rva,count(DISTINCT source_rva) FROM reference "
                            "WHERE module=? AND kind='call' GROUP BY target_rva", (module,)))
    slots = dict(db.execute('SELECT target_rva,count(*) FROM vslot WHERE module=? GROUP BY target_rva', (module,)))
    return [(rva, calls.get(rva, 0), slots.get(rva, 0)) for rva in sorted(set(calls) | set(slots))
            if rva not in known and in_ranges(ranges, rva)]


def relocated_code_pointers(pe, ranges):
    """{target_rva: [slot_rva, ...]} for DIR64 base relocations whose pointer lands in executable bytes."""
    image = pe.get_memory_mapped_image()
    base = pe.OPTIONAL_HEADER.ImageBase
    targets = {}
    for block in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', []):
        for entry in block.entries:
            if entry.type != 10 or entry.rva + 8 > len(image):
                continue
            target = struct.unpack_from('<Q', image, entry.rva)[0] - base
            if in_ranges(ranges, target):
                targets.setdefault(target, []).append(entry.rva)
    return targets, image


def pointer_rows(db, module, pe, known):
    """[(rva, relocation_slots, lea_sites, aligned_after_cc)] for code addresses taken as data."""
    ranges = executable_ranges(db, module)
    relocated, image = relocated_code_pointers(pe, ranges)
    lea = {}
    for source, target in db.execute(
            "SELECT r.source_rva,r.target_rva FROM reference r JOIN instruction i ON i.module=r.module "
            "AND i.rva=r.source_rva WHERE r.module=? AND r.kind='rip' AND i.mnemonic='lea'", (module,)):
        if in_ranges(ranges, target):
            lea.setdefault(target, []).append(source)
    rows = []
    for rva in sorted(set(relocated) | set(lea)):
        if rva in known:
            continue
        aligned = int(rva % 16 == 0 and rva > 0 and image[rva - 1] == 0xCC)
        rows.append((rva, sorted(relocated.get(rva, ())), sorted(lea.get(rva, ())), aligned))
    return rows


def angelscript_rvas(registrations, known):
    """Implementation RVAs from angelscript/registrations.tsv that no earlier pass covered."""
    found = {int(row['implementation_rva'], 16) for row in read_tsv(registrations) if row['implementation_rva']}
    return sorted(found - known)


def hx(rva):
    return f'0x{rva:08x}'


def write_list(path, rvas):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(''.join(f'{hx(rva)}\n' for rva in rvas), encoding='ascii', newline='\n')
    temporary.replace(path)
    return path


def write_rows(path, header, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)
    temporary.replace(path)
    return path


def write_candidates(directory, rows):
    write_rows(Path(directory) / 'candidates.tsv', ('rva', 'direct_call_refs', 'rtti_slot_refs'),
               ((hx(rva), calls, slots) for rva, calls, slots in rows))
    return write_list(Path(directory) / 'candidates.txt', [row[0] for row in rows])


def write_pointers(directory, rows):
    write_rows(Path(directory) / 'pointers.tsv', ('rva', 'relocation_pointer_slots', 'rip_lea_sites', 'aligned_after_cc'),
               ((hx(rva), ','.join(map(hx, slots)), ','.join(map(hx, sites)), aligned)
                for rva, slots, sites, aligned in rows))
    first = write_list(Path(directory) / 'pointers.txt', [row[0] for row in rows if row[3]])
    second = write_list(Path(directory) / 'pointers-extra.txt', [row[0] for row in rows if not row[3]])
    return first, second
