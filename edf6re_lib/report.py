"""out/VERIFICATION.md: every number is read back from the artifacts generate.py just wrote on this machine."""

import csv
import json
from pathlib import Path
import re
import sqlite3
import time

from edf6re_lib import addresses

PCODE_TOTALS = re.compile(r'^; instructions=(\d+) pcode_operations=(\d+)$', re.M)
ANALYSIS_TIMEOUT = re.compile(r'analysis_timed_out_seconds=(\d+)')


def n(value):
    return f'{value:,}' if isinstance(value, int) else str(value)


def table(header, rows, numeric_from=1):
    align = ['---' if i < numeric_from else '---:' for i in range(len(header))]
    lines = ['| ' + ' | '.join(header) + ' |', '| ' + ' | '.join(align) + ' |']
    lines += ['| ' + ' | '.join(n(cell) for cell in row) + ' |' for row in rows]
    return '\n'.join(lines)


def tsv_rows(path):
    with Path(path).open(encoding='utf-8', newline='') as stream:
        return list(csv.DictReader(stream, delimiter='\t'))


def read_json(path):
    path = Path(path)
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else None


def pass_counts(out, module):
    """[(folder, rows, ok, failed)] for every pass that ran, in pass order."""
    counts = []
    for folder in addresses.PASSES:
        index = Path(out) / folder / module / 'functions.tsv'
        if index.exists():
            rows = tsv_rows(index)
            ok = sum(row['status'] == 'ok' for row in rows)
            counts.append((folder, len(rows), ok, len(rows) - ok))
    return counts


def pcode_totals(out):
    totals = []
    for name in ('registrations.pcode', 'handlers.pcode'):
        path = Path(out) / 'angelscript' / name
        if path.exists():
            found = PCODE_TOTALS.findall(path.read_text(encoding='utf-8', errors='replace'))
            if found:
                totals.append((name, int(found[-1][0]), int(found[-1][1])))
    return totals


def binaries(db, modules):
    rows, counts = [], []
    for module in modules:
        image = db.execute('SELECT timestamp,image_base,sha256 FROM image WHERE module=?', (module,)).fetchone()
        if image is None:
            continue
        rows.append((f'`{module}`', f'`0x{image[0]:08X}`', f'`0x{image[1]:X}`', f'`{image[2]}`'))
        size, lines, byte_rows = db.execute("SELECT sum(length(bytes)),count(*),sum(mnemonic='.byte') FROM instruction "
                                            'WHERE module=?', (module,)).fetchone()
        extra = [db.execute(f'SELECT count(*) FROM {name} WHERE module=?', (module,)).fetchone()[0]
                 for name in ('unwind', 'reference', 'vtable', 'vslot')]
        counts.append((f'`{module}`', size or 0, lines, byte_rows or 0, *extra))
    return rows, counts


def write(out, modules, verify_output):
    out = Path(out)
    db = sqlite3.connect((out / 'vanilla.sqlite').as_uri() + '?mode=ro', uri=True)
    try:
        integrity = db.execute('PRAGMA integrity_check').fetchone()[0]
        identity, counts = binaries(db, modules)
        notes = db.execute('SELECT count(*) FROM note').fetchone()[0]
    finally:
        db.close()

    parts = ['# EDF6 original code export verification', '',
             f'Generated on this machine by `generate.py`, {time.strftime("%Y-%m-%d %H:%M")}. Every number below is read back from this run\'s output directory, not copied.', '',
             '## Native disassembly', '',
             table(('File', 'PE TimeDateStamp', 'Preferred base', 'SHA-256'), identity, numeric_from=4), '',
             table(('File', 'Executable bytes', 'Assembly lines', '`.byte` lines', '`.pdata` records', 'Static references', 'RTTI vtables', 'Vtable slots'), counts), '',
             f'SQLite `integrity_check`: `{integrity}`. Project note addresses matched: {n(notes)}. `vanilla.py verify` output:', '',
             '```', verify_output.strip(), '```', '']

    parts += ['## Ghidra passes', '']
    totals = []
    for module in modules:
        passes = pass_counts(out, module)
        if not passes:
            continue
        log = out / 'logs' / f'import.{module}.log'
        timeout = ANALYSIS_TIMEOUT.search(log.read_text(encoding='utf-8', errors='replace')) if log.exists() else None
        status = addresses.exported_status(out, module)
        ok = sum(status.values())
        totals.append((f'`{module}`', len(status), ok, len(status) - ok))
        parts += [f'### `{module}`', '',
                  f'Auto-analysis: {"stopped after reaching the " + timeout.group(1) + " s limit" if timeout else "finished within the limit"}.', '',
                  table(('Pass', 'Exported entries', 'C succeeded', 'Failed'), [(f'`{folder}`', *rest) for folder, *rest in passes]), '']
        lists = []
        for name in addresses.LISTS:
            path = out / 'addresses' / module / name
            if path.exists():
                lists.append((f'`addresses/{module}/{name}`', len(addresses.read_list(path))))
        if lists:
            parts += [table(('Computed address list', 'Addresses'), lists), '']
    if totals:
        parts += ['### Totals', '', table(('File', 'Unique entries', 'With C pseudocode', 'Still failed (timeout)'), totals), '']
    pcode = pcode_totals(out)
    if pcode:
        parts += ['Instruction-level P-code of the timed-out functions:', '', table(('File', 'x64 instructions', 'P-code ops'), pcode), '']

    index = read_json(out / 'function-index' / 'summary.json')
    if index:
        parts += ['## Function index', '', f'`function-index/functions.tsv` has {n(index["unique_entries"])} entries, '
                  f'{n(index["aliases"])} aliases.', '',
                  table(('Code form', 'Entries'), sorted(index['code_kinds'].items())), '',
                  table(('Naming evidence', 'Entries'), sorted(index['names_by_evidence'].items())), '',
                  table(('`.pdata` range', 'Count'), sorted(index['unwind_ranges'].items())), '']

    files = out / 'missions' / 'files.tsv'
    if files.exists():
        rows = tsv_rows(files)
        by_archive = {}
        for row in rows:
            entry = by_archive.setdefault(row['archive'], {'.AC': 0, '.H': 0, '.BVM': 0})
            if not row['error']:
                entry[row['format']] += 1
        bvm = [row for row in rows if row['format'] == '.BVM' and not row['error']]
        usage = tsv_rows(out / 'missions' / 'native-usage.tsv')
        parts += ['## Mission scripts', '',
                  table(('Archive', 'AngelScript', 'Header files', 'BVM listings'),
                        [(f'`{archive}`', c['.AC'], c['.H'], c['.BVM']) for archive, c in by_archive.items()]), '',
                  f'{n(len(rows))} indexed, {n(sum(bool(row["error"]) for row in rows))} with errors. '
                  f'AC: {n(sum(int(row["lines"]) for row in rows if row["format"] == ".AC" and not row["error"]))} lines in total; '
                  f'BVM: {n(sum(int(row["functions"]) for row in bvm))} functions, '
                  f'{n(sum(int(row["instructions"]) for row in bvm))} instructions. '
                  f'The native usage table has {n(len(usage))} `(table, id)` pairs, {n(sum(int(row["call_sites"]) for row in usage))} call sites in total.', '']

    bvm_summary = read_json(out / 'bvm-native' / 'summary.json')
    if bvm_summary:
        flat = [(f'`{key}`', value if not isinstance(value, dict) else json.dumps(value, ensure_ascii=False))
                for key, value in bvm_summary.items() if not key.endswith('sha256')]
        parts += ['## BVM native', '', table(('Item', 'Value'), flat), '']

    parts += ['## Limitations', '',
              'The pseudocode is Ghidra inference: types, control flow and function boundaries must be checked against the assembly; there is no pdb, and names come from RTTI, script bindings, '
              'instruction patterns and `shared/` labels. Functions reached only through runtime computation or indirect calls, with no static reference, may still be unrecognized.', '']
    target = out / 'VERIFICATION.md'
    temporary = target.with_name(target.name + '.tmp')
    temporary.write_text('\n'.join(parts), encoding='utf-8', newline='\n')
    temporary.replace(target)
    return target
