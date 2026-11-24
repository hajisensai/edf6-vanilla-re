"""generate.py 步骤编排的测试：计划顺序、模块筛选、前置检查、--resume、失败续跑命令、--dry-run。

步骤动作换成合成的进程内函数，不调用 Ghidra，也不读游戏文件。
运行：python -B -m unittest discover -s tests -v
"""
from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import generate  # noqa: E402


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.game = self.root / 'game'
        self.game.mkdir()
        self.out = self.root / 'out'
        self.calls = []

    def tearDown(self):
        self.temp.cleanup()

    def pipeline(self, *extra):
        args = generate.parse_args(['--game', str(self.game), '--ghidra', str(self.root / 'ghidra'),
                                    '--out', str(self.out), *extra])
        return generate.Pipeline(args)

    def fake_build(self, fail=None, clean=None):
        """Replace every step with one in-process action that records its key (and fails for `fail`)."""
        def build(pipeline, name, module):
            step = generate.Step(name, module)

            def act(step_log):
                self.calls.append(step.key)
                print(f'ran {step.key}', file=step_log)
                if step.key == fail:
                    raise generate.StepError('synthetic failure')
            step.actions = [generate.Action(f'fake {step.key}', call=act)]
            step.clean = (clean or {}).get(step.key, [])
            return step
        return mock.patch.object(generate.Pipeline, 'build', build)

    def run_quiet(self, pipeline):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = pipeline.run()
        return code, stream.getvalue()

    def test_plan_order_and_module_filter(self):
        with self.fake_build():
            keys = [step.key for step in self.pipeline().plan()]
            exe = [step.key for step in self.pipeline('--module', 'EDF6.exe').plan()]
        self.assertEqual(keys[:3], ['db', 'asm.EDF.dll', 'asm.EDF6.exe'])
        self.assertEqual(keys[-2:], ['index', 'report'])
        self.assertIn('angelscript.EDF.dll', keys)
        self.assertNotIn('angelscript.EDF6.exe', keys)
        self.assertLess(keys.index('candidates.EDF6.exe'), keys.index('pointers.EDF.dll'))
        # EDF6.exe alone: no AngelScript, P-code, mission or BVM steps (they read EDF.dll / the CPKs).
        self.assertEqual(exe, ['db', 'asm.EDF6.exe', 'import.EDF6.exe', 'export.EDF6.exe', 'unwind.EDF6.exe',
                               'retry.EDF6.exe', 'candidates.EDF6.exe', 'pointers.EDF6.exe', 'index', 'report'])

    def test_full_run_writes_markers_and_resume_skips_them(self):
        with self.fake_build():
            code, _ = self.run_quiet(self.pipeline('--module', 'EDF6.exe'))
            self.assertEqual(code, 0)
            first = list(self.calls)
            self.assertTrue((self.out / '.steps' / 'export.EDF6.exe.done').exists())
            self.assertIn('ran db', (self.out / 'logs' / 'db.log').read_text(encoding='utf-8'))
            self.calls.clear()
            code, text = self.run_quiet(self.pipeline('--module', 'EDF6.exe', '--resume'))
        self.assertEqual(code, 0)
        self.assertEqual(self.calls, [])
        self.assertEqual(text.count('skipped (--resume)'), len(first))

    def test_failure_keeps_earlier_markers_and_prints_resume_command(self):
        with self.fake_build(fail='retry.EDF6.exe'):
            code, text = self.run_quiet(self.pipeline('--module', 'EDF6.exe'))
        self.assertEqual(code, 1)
        self.assertEqual(self.calls[-1], 'retry.EDF6.exe')
        self.assertTrue((self.out / '.steps' / 'unwind.EDF6.exe.done').exists())
        self.assertFalse((self.out / '.steps' / 'retry.EDF6.exe.done').exists())
        self.assertIn('synthetic failure', text)
        self.assertIn('--module EDF6.exe --resume', text)
        self.assertIn('--steps retry,candidates,angelscript,pointers,pcode,missions,bvm,index,report', text)
        with self.fake_build():
            self.calls.clear()
            code, _ = self.run_quiet(self.pipeline('--module', 'EDF6.exe', '--resume'))
        self.assertEqual(code, 0)
        self.assertEqual(self.calls, ['retry.EDF6.exe', 'candidates.EDF6.exe', 'pointers.EDF6.exe', 'index', 'report'])

    def test_single_step_needs_finished_prerequisite(self):
        with self.fake_build():
            with self.assertRaisesRegex(generate.StepError, 'candidates.EDF6.exe needs db'):
                self.pipeline('--module', 'EDF6.exe', '--steps', 'candidates').run()
            (self.out / '.steps').mkdir(parents=True)
            for key in ('db', 'retry.EDF6.exe'):
                (self.out / '.steps' / f'{key}.done').write_text('{}', encoding='utf-8')
            code, _ = self.run_quiet(self.pipeline('--module', 'EDF6.exe', '--steps', 'candidates'))
        self.assertEqual(code, 0)
        self.assertEqual(self.calls, ['candidates.EDF6.exe'])

    def test_rerun_cleans_only_the_step_outputs(self):
        mine = self.out / 'pseudocode' / 'EDF6.exe'
        other = self.out / 'pseudocode' / 'EDF.dll'
        for folder in (mine, other):
            folder.mkdir(parents=True)
            (folder / 'functions.tsv').write_text('old', encoding='utf-8')
        (self.out / '.steps').mkdir()
        (self.out / '.steps' / 'import.EDF6.exe.done').write_text('{}', encoding='utf-8')
        with self.fake_build(clean={'export.EDF6.exe': [mine]}):
            code, _ = self.run_quiet(self.pipeline('--module', 'EDF6.exe', '--steps', 'export'))
        self.assertEqual(code, 0)
        self.assertFalse(mine.exists())
        self.assertTrue((other / 'functions.tsv').exists())

    def test_refuses_to_clean_outside_out(self):
        with self.assertRaisesRegex(generate.StepError, 'outside'):
            generate.remove_inside(self.root / 'game', self.out.resolve())
        self.assertTrue(self.game.exists())

    def test_seeded_pass_skips_ghidra_for_empty_list(self):
        pipeline = self.pipeline('--module', 'EDF6.exe')
        action = pipeline.seeded_pass('EDF6.exe', 'retry.txt', 'pseudocode-retry', '-RetryFailed', 'retry')
        log = io.StringIO()
        with mock.patch.object(generate, 'run_command') as run_command:
            action.call(log)
            self.assertFalse(run_command.called)
            generate.addresses.write_list(pipeline.addresses('EDF6.exe') / 'retry.txt', [0x1000])
            action.call(log)
        argv = run_command.call_args.args[0]
        self.assertIn('-RetryFailed', argv)
        self.assertIn(str(pipeline.addresses('EDF6.exe') / 'retry.txt'), argv)
        self.assertIn('empty, no Ghidra pass needed', log.getvalue())

    def test_unknown_step_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            generate.parse_args(['--game', '.', '--steps', 'db,nope'])

    def test_dry_run_prints_real_commands_and_writes_nothing(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'generate.py'), '--game', str(self.game),
                                 '--ghidra', str(self.root / 'ghidra'), '--out', str(self.out), '--dry-run'],
                                capture_output=True, encoding='utf-8', errors='replace', timeout=60, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.out.exists())
        for expected in ('[db] (run)', 'vanilla.py', 'decompile.ps1', '-ImportOnly', '-SeedCandidates',
                         'angelscript_2.28.2.zip', 'function_index.py', '[report] (run)'):
            self.assertIn(expected, result.stdout)


if __name__ == '__main__':
    unittest.main()
