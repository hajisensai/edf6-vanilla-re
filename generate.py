"""One command for the whole local mirror: database, assembly, every Ghidra pass, AngelScript/BVM indexes,
function index and the verification report.

    python -B generate.py --game <EDF6 dir> --ghidra <ghidra_12.1.3_PUBLIC> [--out out] [--resume]

Every step is idempotent and can run alone (--steps). A finished step leaves out/.steps/<step>[.<module>].done;
--resume skips those. Each step logs to out/logs/. Address lists that seed the later Ghidra passes are computed
from vanilla.sqlite and the earlier exports (edf6re_lib/addresses.py).
"""

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from edf6re_lib import addresses  # noqa: E402
from edf6re_lib.paths import ENV as OUT_ENV  # noqa: E402

MODULES = ('EDF.dll', 'EDF6.exe')
PROJECTS = {'EDF.dll': 'game', 'EDF6.exe': 'launcher'}
SDK_NAME = 'angelscript_2.28.2.zip'
SDK_URL = 'https://www.angelcode.com/angelscript/sdk/files/angelscript_2.28.2.zip'
SDK_SHA256 = '54bc6126d2ba2509f3916ff139758d3c3c2185dddb521fc040110c5afde6000a'
PCODE = (('registrations.asm', 'registrations.pcode'), ('handlers.asm', 'handlers.pcode'))
HEARTBEAT_SECONDS = 60

# (name, per-module?, modules it applies to, steps it needs, help)
STEPS = (
    ('db', False, MODULES, (), 'vanilla.py build: SQLite of sections, .pdata, instructions, references, RTTI'),
    ('asm', True, MODULES, ('db',), 'vanilla.py asm: one instruction per line'),
    ('import', True, MODULES, (), 'Ghidra import + auto-analysis (decompile.ps1 -ImportOnly)'),
    ('export', True, MODULES, ('import',), 'Ghidra C export of the analyzed functions -> pseudocode/'),
    ('unwind', True, MODULES, ('export',), '.pdata starts Ghidra did not make functions -> pseudocode-unwind/'),
    ('retry', True, MODULES, ('unwind',), 'failed exports with a longer per-function timeout -> pseudocode-retry/'),
    ('candidates', True, MODULES, ('db', 'retry'), 'direct-call and RTTI-slot targets -> pseudocode-candidates/'),
    ('angelscript', True, ('EDF.dll',), ('candidates',),
     'AngelScript registration table (SDK 2.28.2) and its native entries -> angelscript/, pseudocode-angelscript/'),
    ('pointers', True, MODULES, ('candidates',),
     'relocated / RIP-lea code pointers, INT3-aligned first -> pseudocode-pointers/, pseudocode-pointers-extra/'),
    ('pcode', True, ('EDF.dll',), ('angelscript',), 'instruction-level P-code of the two oversized functions'),
    ('missions', False, ('EDF.dll',), (), 'mission AC/BVM sources and BVM native usage from the CPKs -> missions/'),
    ('bvm', False, ('EDF.dll',), ('missions',), 'BVM native dispatcher probe and ABI index -> bvm-native/'),
    ('index', False, MODULES, ('db', 'pointers'), 'function_index.py: names and RVAs of every entry -> function-index/'),
    ('report', False, MODULES, ('db',), 'vanilla.py verify plus counts -> 验证.md'),
)
STEP_NAMES = tuple(step[0] for step in STEPS)


class StepError(RuntimeError):
    pass


@dataclass
class Action:
    """A command (argv) or an in-process function (call) with a printable description."""
    describe: str
    argv: list = None
    call: object = None
    log_name: str = None


@dataclass
class Step:
    name: str
    module: str = None
    actions: list = field(default_factory=list)
    clean: list = field(default_factory=list)

    @property
    def key(self):
        return self.name if self.module is None else f'{self.name}.{self.module}'


class Pipeline:
    def __init__(self, args):
        self.args = args
        self.out = args.out.resolve()
        self.game = args.game.resolve()
        self.ghidra = args.ghidra.resolve() if args.ghidra else None
        self.python = [sys.executable, '-B']
        self.modules = MODULES if args.module == 'all' else (args.module,)

    # -- paths -----------------------------------------------------------------------------------
    @property
    def steps_dir(self):
        return self.out / '.steps'

    @property
    def logs(self):
        return self.out / 'logs'

    def marker(self, key):
        return self.steps_dir / f'{key}.done'

    def addresses(self, module):
        return self.out / 'addresses' / module

    def project(self, module, suffix=''):
        name = PROJECTS[module] + suffix
        projects = self.out / '_cache' / 'projects'
        return [projects / f'{name}.gpr', projects / f'{name}.rep']

    def script(self, name):
        return [*self.python, str(ROOT / name)]

    def unofficial(self):
        return ['--allow-unofficial'] if self.args.allow_unofficial else []

    def decompile(self, module, *extra, log):
        if self.ghidra is None:
            raise StepError('--ghidra is required for the Ghidra steps')
        argv = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                '-File', str(ROOT / 'decompile.ps1'), '-Game', str(self.game), '-Ghidra', str(self.ghidra),
                '-Module', module, '-Workers', str(self.args.workers), '-OutRoot', str(self.out),
                '-Python', sys.executable, '-Log', str(self.logs / f'ghidra-{log}.log')]
        if self.args.java:
            argv += ['-Java', str(self.args.java)]
        if self.args.allow_unofficial:
            argv.append('-AllowUnofficial')
        if self.args.no_shared_labels:
            argv.append('-NoSharedLabels')
        return argv + [str(item) for item in extra]

    # -- steps -----------------------------------------------------------------------------------
    def build(self, name, module):
        return getattr(self, 'step_' + name.replace('-', '_'))(module)

    def step_db(self, _module):
        argv = self.script('vanilla.py') + ['--db', str(self.out / 'vanilla.sqlite'), 'build', str(self.game),
                                            '--modules', ','.join(self.modules)] + self.unofficial()
        if self.args.notes_dir:
            argv += ['--notes-dir', str(self.args.notes_dir.resolve())]
        return Step('db', actions=[Action('build vanilla.sqlite', argv)])

    def step_asm(self, module):
        target = self.out / 'assembly' / f'{module}.asm'
        argv = self.script('vanilla.py') + ['--db', str(self.out / 'vanilla.sqlite'), '--module', module, 'asm', str(target)]
        return Step('asm', module, [Action(f'mkdir {target.parent}', call=lambda: target.parent.mkdir(parents=True, exist_ok=True)),
                                    Action(f'write {target}', argv)], clean=[target])

    def step_import(self, module):
        argv = self.decompile(module, '-ImportOnly', '-AnalysisTimeoutSeconds', self.args.analysis_timeout,
                              log=f'import-{module}')
        return Step('import', module, [Action(f'Ghidra import + analysis of {module}', argv)],
                    clean=self.project(module) + self.project(module, '-unwind'))

    def step_export(self, module):
        output = self.out / 'pseudocode'
        argv = self.decompile(module, '-ReuseProject', '-Output', output, log=f'export-{module}')
        return Step('export', module, [Action(f'Ghidra C export -> {output / module}', argv)], clean=[output / module])

    def step_unwind(self, module):
        output = self.out / 'pseudocode-unwind'
        argv = self.decompile(module, '-ReuseProject', '-Unwind', '-Output', output, log=f'unwind-{module}')
        return Step('unwind', module, [Action(f'seed .pdata starts -> {output / module}', argv)], clean=[output / module])

    def seeded_pass(self, module, list_name, folder, mode, log, extra=()):
        """Ghidra pass over a computed address list; skipped (with a note) when the list is empty."""
        address_list = self.addresses(module) / list_name
        argv = self.decompile(module, '-ReuseProject', mode, '-AddressList', address_list,
                              '-Output', self.out / folder, *extra, log=log)

        def run(step_log):
            rvas = addresses.read_list(address_list)
            if not rvas:
                print(f'{address_list.name}: empty, no Ghidra pass needed', file=step_log, flush=True)
                return
            run_command(argv, step_log)
        return Action(f'Ghidra {mode} over {address_list} -> {self.out / folder / module}\n    '
                      + format_command(argv) + '   (skipped when the list is empty)', call=run)

    def step_retry(self, module):
        def compute(step_log):
            rvas = addresses.retry_rvas(self.out, module)
            addresses.write_list(self.addresses(module) / 'retry.txt', rvas)
            print(f'retry.txt: {len(rvas)} failed entries', file=step_log, flush=True)
        extra = ('-TimeoutSeconds', self.args.retry_timeout)
        return Step('retry', module, [
            Action(f'compute {self.addresses(module) / "retry.txt"} from failed rows of pseudocode*/functions.tsv', call=compute),
            self.seeded_pass(module, 'retry.txt', 'pseudocode-retry', '-RetryFailed', f'retry-{module}', extra)],
            clean=[self.out / 'pseudocode-retry' / module, self.addresses(module) / 'retry.txt'])

    def step_candidates(self, module):
        def compute(step_log):
            with self.database() as db:
                rows = addresses.candidate_rows(db, module, addresses.known_before(self.out, module, 'pseudocode-candidates'))
            addresses.write_candidates(self.addresses(module), rows)
            print(f'candidates.txt: {len(rows)} call / vtable-slot targets', file=step_log, flush=True)
        return Step('candidates', module, [
            Action(f'compute {self.addresses(module) / "candidates.tsv"} from vanilla.sqlite call refs and RTTI slots', call=compute),
            self.seeded_pass(module, 'candidates.txt', 'pseudocode-candidates', '-SeedCandidates', f'candidates-{module}')],
            clean=[self.out / 'pseudocode-candidates' / module] +
                  [self.addresses(module) / name for name in ('candidates.tsv', 'candidates.txt')])

    def step_angelscript(self, module):
        sdk = self.out / '_cache' / SDK_NAME
        output = self.out / 'angelscript'
        argv = self.script('angelscript_index.py') + [str(self.game / module), '--sdk', str(sdk),
                                                      '--output', str(output)] + self.unofficial()

        def compute(step_log):
            known = addresses.known_before(self.out, module, 'pseudocode-angelscript')
            rvas = addresses.angelscript_rvas(output / 'registrations.tsv', known)
            addresses.write_list(self.addresses(module) / 'angelscript.txt', rvas)
            print(f'angelscript.txt: {len(rvas)} registered natives not exported yet', file=step_log, flush=True)
        return Step('angelscript', module, [
            Action(f'fetch {SDK_URL} -> {sdk} (sha256 {SDK_SHA256})', call=lambda step_log: fetch_sdk(sdk, self.args.sdk, step_log)),
            Action(f'index AngelScript registrations -> {output}', argv),
            Action(f'compute {self.addresses(module) / "angelscript.txt"} from angelscript/registrations.tsv', call=compute),
            self.seeded_pass(module, 'angelscript.txt', 'pseudocode-angelscript', '-SeedCandidates', f'angelscript-{module}')],
            clean=[output, self.out / 'pseudocode-angelscript' / module, self.addresses(module) / 'angelscript.txt'])

    def step_pointers(self, module):
        def compute(step_log):
            import pefile
            pe = pefile.PE(str(self.game / module), fast_load=True)
            pe.parse_data_directories(directories=[5])
            with self.database() as db:
                rows = addresses.pointer_rows(db, module, pe, addresses.known_before(self.out, module, 'pseudocode-pointers'))
            addresses.write_pointers(self.addresses(module), rows)
            aligned = sum(row[3] for row in rows)
            print(f'pointers.txt: {aligned} INT3-aligned, pointers-extra.txt: {len(rows) - aligned} others',
                  file=step_log, flush=True)
        names = ('pointers.tsv', 'pointers.txt', 'pointers-extra.txt')
        return Step('pointers', module, [
            Action(f'compute {self.addresses(module) / "pointers.tsv"} from base relocations and RIP lea in vanilla.sqlite', call=compute),
            self.seeded_pass(module, 'pointers.txt', 'pseudocode-pointers', '-SeedCandidates', f'pointers-{module}'),
            self.seeded_pass(module, 'pointers-extra.txt', 'pseudocode-pointers-extra', '-SeedCandidates', f'pointers-extra-{module}')],
            clean=[self.out / 'pseudocode-pointers' / module, self.out / 'pseudocode-pointers-extra' / module] +
                  [self.addresses(module) / name for name in names])

    def step_pcode(self, module):
        folder = self.out / 'angelscript'
        extra = ['-ReuseProject', '-IrInput', ','.join(str(folder / a) for a, _ in PCODE),
                 '-IrOutput', ','.join(str(folder / b) for _, b in PCODE)]
        argv = self.decompile(module, *extra, log=f'pcode-{module}')
        return Step('pcode', module, [Action('Ghidra P-code of ' + ', '.join(a for a, _ in PCODE), argv)],
                    clean=[folder / b for _, b in PCODE])

    def step_missions(self, _module):
        output = self.out / 'missions'
        argv = self.script('missions.py') + [str(self.game), '--output', str(output)] + self.unofficial()
        return Step('missions', actions=[Action(f'export mission scripts -> {output}', argv)], clean=[output])

    def step_bvm(self, _module):
        trace = self.out / '_cache' / 'bvm-native-trace.jsonl'
        output = self.out / 'bvm-native'
        probe = self.script('bvm_native_probe.py') + [str(self.game / 'EDF.dll'), '--usage',
                                                       str(self.out / 'missions' / 'native-usage.tsv'),
                                                       '--output', str(trace)] + self.unofficial()
        index = self.script('bvm_native_index.py') + [str(self.game), str(trace), '--output', str(output)] + self.unofficial()
        return Step('bvm', actions=[Action(f'mkdir {trace.parent}', call=lambda: trace.parent.mkdir(parents=True, exist_ok=True)),
                                    Action(f'probe BVM natives -> {trace}', probe),
                                    Action(f'index BVM natives -> {output}', index)],
                    clean=[trace, trace.with_name(trace.name + '.provenance.json'), output])

    def step_index(self, _module):
        output = self.out / 'function-index'
        argv = self.script('function_index.py') + ['--output', str(output)]
        return Step('index', actions=[Action(f'merge every pass -> {output}', argv)], clean=[output])

    def step_report(self, _module):
        from edf6re_lib import report
        verify_log = self.logs / 'report-verify.txt'
        argv = self.script('vanilla.py') + ['--db', str(self.out / 'vanilla.sqlite'), 'verify', str(self.game)] + self.unofficial()

        def write(step_log):
            target = report.write(self.out, self.modules, verify_log.read_text(encoding='utf-8'))
            print(f'wrote {target}', file=step_log, flush=True)
        return Step('report', actions=[Action(f'vanilla.py verify -> {verify_log}', argv, log_name=verify_log),
                                       Action(f'write {self.out / "验证.md"}', call=write)],
                    clean=[self.out / '验证.md', verify_log])

    def database(self):
        import contextlib
        import sqlite3

        @contextlib.contextmanager
        def opened():
            db = sqlite3.connect((self.out / 'vanilla.sqlite').as_uri() + '?mode=ro', uri=True)
            try:
                yield db
            finally:
                db.close()
        return opened()

    # -- orchestration ---------------------------------------------------------------------------
    def plan(self):
        wanted = self.args.steps or list(STEP_NAMES)
        plan = []
        for name, per_module, applies, _, _ in STEPS:
            if name not in wanted:
                continue
            modules = [m for m in self.modules if m in applies]
            if not modules:
                continue
            if per_module:
                plan.extend(self.build(name, module) for module in modules)
            else:
                plan.append(self.build(name, None))
        return plan

    def check_requirements(self, plan):
        planned = {step.key for step in plan}
        for step in plan:
            needs = next(item[3] for item in STEPS if item[0] == step.name)
            for need in needs:
                per_module = next(item[1] for item in STEPS if item[0] == need)
                applies = next(item[2] for item in STEPS if item[0] == need)
                modules = [step.module] if step.module else self.modules
                for module in modules:
                    if per_module and module not in applies:
                        continue
                    key = f'{need}.{module}' if per_module else need
                    if key not in planned and not self.marker(key).exists():
                        raise StepError(f'{step.key} needs {key}, which has not finished. '
                                        f'Run it first: {self.command(need)}')

    def command(self, first_step=None, resume=False):
        """The command line that continues this run (from first_step on, or with --resume)."""
        argv = ['python', '-B', 'generate.py', '--game', str(self.game), '--out', str(self.out)]
        if self.ghidra:
            argv += ['--ghidra', str(self.ghidra)]
        if self.args.java:
            argv += ['--java', str(self.args.java)]
        if self.args.module != 'all':
            argv += ['--module', self.args.module]
        if self.args.allow_unofficial:
            argv.append('--allow-unofficial')
        if first_step:
            wanted = self.args.steps or list(STEP_NAMES)
            later = [name for name in STEP_NAMES if name in wanted and STEP_NAMES.index(name) >= STEP_NAMES.index(first_step)]
            argv += ['--steps', ','.join(later)]
        if resume:
            argv.append('--resume')
        return format_command(argv)

    def run(self):
        plan = self.plan()
        if self.args.dry_run:
            print(f'# {OUT_ENV}={self.out}')
            for step in plan:
                state = 'done, skipped with --resume' if self.args.resume and self.marker(step.key).exists() else 'run'
                print(f'\n[{step.key}] ({state})  log: {self.logs / (step.key + ".log")}')
                for path in step.clean:
                    print(f'  clean {path}')
                for action in step.actions:
                    print('  ' + (format_command(action.argv) if action.argv else action.describe))
            return 0
        self.check_requirements(plan)
        self.logs.mkdir(parents=True, exist_ok=True)
        self.steps_dir.mkdir(parents=True, exist_ok=True)
        os.environ[OUT_ENV] = str(self.out)
        started_all = time.monotonic()
        for step in plan:
            if self.args.resume and self.marker(step.key).exists():
                print(f'[{step.key}] done before, skipped (--resume)', flush=True)
                continue
            log = self.logs / f'{step.key}.log'
            print(f'[{step.key}] start  log: {log}', flush=True)
            started = time.monotonic()
            self.marker(step.key).unlink(missing_ok=True)
            try:
                for path in step.clean:
                    remove_inside(path, self.out)
                with log.open('w', encoding='utf-8') as step_log:
                    for action in step.actions:
                        print(f'== {action.describe}', file=step_log, flush=True)
                        with heartbeat(step.key, started):
                            if action.argv:
                                target = Path(action.log_name) if action.log_name else None
                                run_command(action.argv, step_log, target)
                            elif action.call.__code__.co_argcount:
                                action.call(step_log)
                            else:
                                action.call()
            except (StepError, OSError, ValueError, subprocess.CalledProcessError) as error:
                print(f'[{step.key}] FAILED after {time.monotonic() - started:.0f}s: {error}', flush=True)
                print_tail(log)
                print(f'Log: {log}\nFix the cause, then continue with:\n  {self.command(resume=True)}\n'
                      f'or rerun only from this step:\n  {self.command(step.name)}', flush=True)
                return 1
            elapsed = time.monotonic() - started
            self.marker(step.key).write_text(json.dumps({'step': step.key, 'seconds': round(elapsed, 1),
                                                         'finished': time.strftime('%Y-%m-%d %H:%M:%S')}) + '\n',
                                             encoding='utf-8')
            print(f'[{step.key}] done in {elapsed:.0f}s', flush=True)
        print(f'[all] finished in {time.monotonic() - started_all:.0f}s', flush=True)
        return 0


def format_command(argv):
    return ' '.join(shlex.quote(str(item)) if any(c in str(item) for c in ' \'"') else str(item) for item in argv)


def run_command(argv, step_log, capture=None):
    print('$ ' + format_command(argv), file=step_log, flush=True)
    env = dict(os.environ, PYTHONIOENCODING='utf-8', PYTHONUTF8='1')
    if capture:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=step_log, env=env, cwd=ROOT)
        capture.write_bytes(result.stdout)
        step_log.write(result.stdout.decode('utf-8', errors='replace'))
        step_log.flush()
    else:
        result = subprocess.run(argv, stdout=step_log, stderr=subprocess.STDOUT, env=env, cwd=ROOT)
    if result.returncode:
        program = argv[6] if argv[0] == 'powershell.exe' else argv[2] if len(argv) > 2 else argv[0]
        raise StepError(f'{Path(str(program)).name} exited {result.returncode}')


class heartbeat:
    """Print '[heartbeat] <step> <seconds>s' every HEARTBEAT_SECONDS while a long action runs."""

    def __init__(self, key, started):
        self.key, self.started = key, started
        self.stop = threading.Event()

    def __enter__(self):
        def beat():
            while not self.stop.wait(HEARTBEAT_SECONDS):
                print(f'[heartbeat] {self.key} {time.monotonic() - self.started:.0f}s', flush=True)
        self.thread = threading.Thread(target=beat, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join()


def remove_inside(path, root):
    path = Path(path).resolve()
    if root not in path.parents:
        raise StepError(f'refusing to delete {path}: outside {root}')
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def print_tail(log, lines=15):
    try:
        text = log.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return
    for line in text[-lines:]:
        print('  | ' + line)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def fetch_sdk(target, local, step_log):
    """Put the official AngelScript 2.28.2 SDK at target, from --sdk or the official URL, checked by SHA-256."""
    if target.exists() and sha256(target) == SDK_SHA256:
        print(f'{target.name}: present, sha256 ok', file=step_log, flush=True)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + '.part')
    if local:
        shutil.copyfile(local, partial)
        print(f'copied {local}', file=step_log, flush=True)
    else:
        print(f'downloading {SDK_URL}', file=step_log, flush=True)
        request = urllib.request.Request(SDK_URL, headers={'User-Agent': 'edf6-vanilla-re'})
        with urllib.request.urlopen(request, timeout=120) as response, partial.open('wb') as stream:
            shutil.copyfileobj(response, stream)
    actual = sha256(partial)
    if actual != SDK_SHA256:
        partial.unlink()
        raise StepError(f'{SDK_NAME} sha256 {actual} != {SDK_SHA256}; download it from {SDK_URL} and pass --sdk')
    partial.replace(target)
    print(f'{target.name}: sha256 ok', file=step_log, flush=True)


def step_list(text):
    names = [name.strip() for name in text.split(',') if name.strip()]
    unknown = [name for name in names if name not in STEP_NAMES]
    if unknown or not names:
        raise argparse.ArgumentTypeError(f'unknown step {",".join(unknown) or "(none)"}; choose from {",".join(STEP_NAMES)}')
    return names


def parse_args(argv=None):
    steps = '\n'.join(f'  {name:12} {"per module" if per else "once":10} {text}' for name, per, _, _, text in STEPS)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog='steps, in order:\n' + steps)
    parser.add_argument('--game', type=Path, required=True, help='EDF6 install directory (read only)')
    parser.add_argument('--ghidra', type=Path, help='Ghidra 12.1.3 directory (needed by import/export/... steps)')
    parser.add_argument('--java', type=Path, help='java.exe of JDK 21 (default: java.exe on PATH)')
    parser.add_argument('--out', type=Path, default=ROOT / 'out', help='artifact root (default: out/)')
    parser.add_argument('--steps', type=step_list, help='comma-separated subset of steps, run in pipeline order')
    parser.add_argument('--module', choices=(*MODULES, 'all'), default='all', help='PE image(s) to process (default: all)')
    parser.add_argument('--resume', action='store_true', help='skip steps whose out/.steps marker exists')
    parser.add_argument('--dry-run', action='store_true', help='print what each step would run, run nothing')
    parser.add_argument('--allow-unofficial', action='store_true', help='generate from unverified game files (recorded)')
    parser.add_argument('--workers', type=int, default=6, help='Ghidra worker threads (default: 6)')
    parser.add_argument('--analysis-timeout', type=int, default=430,
                        help='seconds of Ghidra auto-analysis per file, 0 = unlimited (default: 430)')
    parser.add_argument('--retry-timeout', type=int, default=45, help='per-function seconds in the retry pass (default: 45)')
    parser.add_argument('--sdk', type=Path, help=f'local {SDK_NAME} instead of downloading it')
    parser.add_argument('--notes-dir', type=Path, help='Markdown notes whose RVA mentions vanilla.sqlite indexes')
    parser.add_argument('--no-shared-labels', action='store_true', help='do not import shared/ names into Ghidra')
    return parser.parse_args(argv)


def main(argv=None):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    args = parse_args(argv)
    try:
        return Pipeline(args).run()
    except StepError as error:
        print(f'error: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
