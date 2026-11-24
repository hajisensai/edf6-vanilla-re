"""Turn BVM dispatcher traces and original scripts into a versioned ABI index."""

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path

from verify_install import gate_or_exit, write_provenance
import struct
import sys


from edf6re_lib.paths import out_root

ROOT = Path(__file__).resolve().parent
OUT = out_root()   # every generated artifact lives here: $EDF6RE_OUT or <repo>/out (git-ignored)


def fmt(address):
    return '' if address is None else f'0x{address:08X}'


def read_tsv(path):
    with path.open(encoding='utf-8', newline='') as source:
        return list(csv.DictReader(source, delimiter='\t'))


def write_tsv(path, header, rows):
    with path.open('x', encoding='utf-8', newline='') as file:
        output = csv.writer(file, delimiter='\t', lineterminator='\n')
        output.writerow(header)
        output.writerows(rows)


def parameters(probe):
    delta = probe['delta']
    writes = {offset // 8: width for offset, width, _ in probe['writes']}
    result_widths = []
    while delta - len(result_widths) in writes:
        result_widths.append(writes[delta - len(result_widths)])
    result_widths.reverse()
    count = max([len(result_widths) - delta, 0] + [1 - offset // 8 for offset, _, _, _ in probe['reads']])
    kinds = [set() for _ in range(count)]
    sources = [set() for _ in range(count)]
    for offset, _, kind, rva in probe['reads']:
        slot = offset // 8 + count - 1
        kinds[slot].add(kind)
        sources[slot].add(rva)
    types = ''.join(next(iter(kind)) if len(kind) == 1 else '?' for kind in kinds)
    return (delta, types, tuple(result_widths)), sources


def load_probes(path, usage, image_hash):
    probes = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        record = json.loads(line)
        if record['edf_sha256'] != image_hash:
            raise ValueError('BVM traces and the installed EDF.dll have different SHA-256 values')
        key = record['table'], record['id']
        successful = [case for name, case in record['cases'].items()
                      if name != 'muted_results' and case['delta'] is not None]
        shapes = {parameters(case)[0] for case in successful}
        if len(shapes) != 1:
            raise ValueError(f'{key} has no consistent observed dispatcher signature: {shapes}')
        delta, types, widths = shapes.pop()
        commits = [case['delta'] for case in record['cases'].values() if case['delta'] is not None]
        if any(commit != delta for commit in commits):
            raise ValueError(f'{key} has conflicting stack deltas: {commits}')
        previous = usage[key]
        if previous['signature_known'] == '1':
            need = len(previous['param_types']), int(previous['return_count']), int(previous['stack_delta_from_NET6'])
            observed = len(types), len(widths), delta
            if need != observed:
                raise ValueError(f'{key} baseline mismatch {need} != {observed}')
        sources = [set() for _ in types]
        for case in successful:
            for seen, addresses in zip(sources, parameters(case)[1]):
                seen.update(addresses)
        probes[key] = (delta, types, widths, sources, successful, record['cases'])
    if probes.keys() != usage.keys():
        raise ValueError('Probe IDs differ from the original-script usage index')
    return probes


def verify_scripts(game, probes):
    from edf6re_lib import bvm41, rootcpk

    signatures = {(bvm41.OP_NAT0 + t, n): ('?' * len(types), len(widths))
                  for (t, n), (_, types, widths, *_rest) in probes.items()}
    effects = {(bvm41.OP_NAT0 + t, n): delta for (t, n), (delta, *_rest) in probes.items()}
    source = rootcpk.Game(str(game))
    evidence = {key: [Counter() for _ in shape[1]] for key, shape in probes.items()}
    witness = {}
    counts, reachable = Counter(), Counter()
    issues = []
    catalog = {(row['archive'], row['source'].upper()): row for row in read_tsv(OUT / 'missions/files.tsv')}
    verified_files = set()
    for directory, name in sorted(source.cpk.index):
        if directory.split('/')[0].upper() != 'MISSION' or not name.upper().endswith('.BVM'):
            continue
        path = f'{directory}/{name}'
        data = source.read(directory, name)
        row = catalog[('Root.cpk', path.upper())]
        if hashlib.sha256(data).hexdigest() != row['source_sha256']:
            raise ValueError(f'{path}: archive fingerprint differs from the exported script')
        verified_files.add(path)
        prog = bvm41.parse(data)
        header = struct.unpack_from('<20I', data)
        decoded = bvm41._decode(data, header[12], header[14])
        offset_start = len(prog.init)
        offsets = {}
        for function in prog.funcs:
            offsets[id(function)] = offset_start
            offset_start += len(function.code)
        for code in [prog.init, *(f.code for f in prog.funcs)]:
            for ins in code:
                if ins.op in bvm41.OP_NATIVE:
                    counts[(ins.op - bvm41.OP_NAT0, ins.v)] += 1
        issues.extend((path, 'stack', message) for message in bvm41.stack_check(prog, effects))

        def visit(function, index, instruction, args):
            key = instruction.op - bvm41.OP_NAT0, instruction.v
            if args is None:
                issues.append((path, 'argument_walk', f'{function.name} instruction {index}: {key} missing operands'))
                return
            reachable[key] += 1
            for slot, arg in enumerate(args):
                for kind in {kind for kind, _ in arg.values}:
                    evidence[key][slot][kind] += 1
                    witness.setdefault((key, slot, kind), (path, function.name, fmt(decoded[offsets[id(function)] + index][0])))

        try:
            bvm41._walk(prog, signatures, visit)
        except ValueError as error:
            issues.append((path, 'argument_walk', str(error)))
    report_files = {row['source'] for row in catalog.values() if row['format'] == '.BVM'}
    if verified_files != report_files:
        raise ValueError('The archived BVM file list differs from the exported index')
    return len(verified_files), counts, reachable, evidence, witness, issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('game', type=Path)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-unofficial', action='store_true', help='generate from unverified game files; recorded in provenance.json')
    args = parser.parse_args()
    provenance = gate_or_exit(parser, args.game, ('EDF.dll', 'Root.cpk'), args.allow_unofficial, 'bvm_native_index.py')
    usage = {(int(row['native_table']), int(row['native_id'])): row
             for row in read_tsv(OUT / 'missions/native-usage.tsv')}
    image_hash = hashlib.sha256((args.game / 'EDF.dll').read_bytes()).hexdigest()
    probes = load_probes(args.trace, usage, image_hash)
    files, counts, reachable, evidence, witness, issues = verify_scripts(args.game, probes)
    if any(counts[key] != int(row['call_sites']) for key, row in usage.items()):
        raise ValueError('Disagreement with the original BVM export call counts')
    signatures, slots, fixture_checks = [], [], []
    unnamed = Counter()
    for key, (delta, types, widths, read_addresses, cases, fixtures) in sorted(probes.items()):
        row = usage[key]
        args_text = ''
        observed = ''.join(types)
        for index, storage in enumerate(types):
            kinds = evidence[key][index]
            preferred = storage
            if storage == 'q' and kinds['s'] and not kinds['i'] and not kinds['f']:
                preferred = 'p'
            if storage == 'q' and preferred == 'q' and row['signature_known'] == '0':
                unnamed[key] += 1
            args_text += preferred
            sites = [(kind, witness[key, index, kind]) for kind in ('s', 'f', 'i', '?') if kinds[kind]]
            slots.append((*key, index + 1, storage, preferred, ','.join(fmt(a) for a in sorted(read_addresses[index])),
                          kinds['s'], kinds['f'], kinds['i'], kinds['?'], json.dumps(sites, ensure_ascii=False)))
        entries = {c['entry'] for c in cases if c['entry'] is not None}
        if not entries:
            entries = {0x20FFE0} if key[0] == 3 else set()
        calls = {pair for case in cases for pair in map(tuple, case['calls'])}
        signatures.append((*key, counts[key], reachable[key], row['signature_known'], row['param_types'], observed,
                           args_text, len(types), len(widths), delta, ','.join(str(w * 8) for w in widths),
                           ','.join(fmt(entry) for entry in sorted(entries)),
                           ','.join(f'{fmt(rva)}->{target}' for rva, target in sorted(calls)),
                           sum(c['delta'] is not None for c in fixtures.values()), len(fixtures)))
        for fixture, case in fixtures.items():
            fixture_checks.append((*key, fixture, fmt(case['entry']), case['delta'], fmt(case['last']), case['failure']))
    args.output.mkdir(parents=True, exist_ok=False)
    write_provenance(args.output, provenance)
    write_tsv(args.output / 'signatures.tsv', ('table','id','calls','reachable_script_calls','registry_signature_known',
              'registry_param_types','observed_slot_types','indexed_param_types','params','returns','stack_delta',
              'return_width_bits','dispatch_entry_rvas','native_call_sites','committed_fixtures','total_fixtures'), signatures)
    write_tsv(args.output / 'arguments.tsv', ('table','id','arg','slot_type','indexed_type','read_rvas','script_strings',
              'script_floats','script_integers','script_unknowns','script_witnesses'), slots)
    write_tsv(args.output / 'fixture-results.tsv', ('table','id','fixture','dispatch_entry_rva','stack_delta','last_rva','stop_reason'),
              fixture_checks)
    write_tsv(args.output / 'script-checks.tsv', ('path','check','detail'), issues)
    summary = {'edf_sha256': image_hash, 'ids': len(probes),
               'added_ids': sum(row['signature_known'] == '0' for row in usage.values()),
               'confirmed_script_files': files, 'indexed_native_sites': sum(counts.values()),
               'reachable_native_sites_checked': sum(reachable.values()),
               'new_ids_with_opaque_64bit_slots': len(unnamed), 'new_opaque_64bit_slots': sum(unnamed.values()),
               'script_issues_by_type': dict(Counter(check for _, check, _ in issues))}
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
