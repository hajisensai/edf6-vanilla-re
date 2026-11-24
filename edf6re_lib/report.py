"""out/验证.md: every number is read back from the artifacts generate.py just wrote on this machine."""

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

    parts = ['# EDF6 原版代码导出核对', '',
             f'本机由 `generate.py` 生成，{time.strftime("%Y-%m-%d %H:%M")}。下面每个数字都从本次输出目录读回，不是抄来的。', '',
             '## 原生反汇编', '',
             table(('文件', 'PE TimeDateStamp', '首选基址', 'SHA-256'), identity, numeric_from=4), '',
             table(('文件', '可执行字节', '汇编行', '`.byte` 行', '`.pdata` 记录', '静态引用', 'RTTI 虚表', '虚表槽'), counts), '',
             f'SQLite `integrity_check`：`{integrity}`。项目笔记地址匹配 {n(notes)} 条。`vanilla.py verify` 输出：', '',
             '```', verify_output.strip(), '```', '']

    parts += ['## Ghidra 各轮', '']
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
                  f'自动分析：{"达到 " + timeout.group(1) + " 秒时限后停止" if timeout else "在时限内完成"}。', '',
                  table(('轮次', '导出条目', 'C 成功', '失败'), [(f'`{folder}`', *rest) for folder, *rest in passes]), '']
        lists = []
        for name in addresses.LISTS:
            path = out / 'addresses' / module / name
            if path.exists():
                lists.append((f'`addresses/{module}/{name}`', len(addresses.read_list(path))))
        if lists:
            parts += [table(('自动算出的地址清单', '地址数'), lists), '']
    if totals:
        parts += ['### 合计', '', table(('文件', '唯一入口', '有 C 伪代码', '仍失败（超时）'), totals), '']
    pcode = pcode_totals(out)
    if pcode:
        parts += ['超时函数的逐指令 P-code：', '', table(('文件', 'x64 指令', 'P-code 操作'), pcode), '']

    index = read_json(out / 'function-index' / 'summary.json')
    if index:
        parts += ['## 函数总表', '', f'`function-index/functions.tsv` 共 {n(index["unique_entries"])} 个入口，'
                  f'别名 {n(index["aliases"])} 条。', '',
                  table(('代码形式', '入口'), sorted(index['code_kinds'].items())), '',
                  table(('命名依据', '入口'), sorted(index['names_by_evidence'].items())), '',
                  table(('`.pdata` 区间', '数量'), sorted(index['unwind_ranges'].items())), '']

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
        parts += ['## 任务脚本', '',
                  table(('归档', 'AngelScript', '头文件', 'BVM 清单'),
                        [(f'`{archive}`', c['.AC'], c['.H'], c['.BVM']) for archive, c in by_archive.items()]), '',
                  f'索引 {n(len(rows))} 条，出错 {n(sum(bool(row["error"]) for row in rows))} 条。'
                  f'AC 共 {n(sum(int(row["lines"]) for row in rows if row["format"] == ".AC" and not row["error"]))} 行；'
                  f'BVM 共 {n(sum(int(row["functions"]) for row in bvm))} 个函数、'
                  f'{n(sum(int(row["instructions"]) for row in bvm))} 条指令。'
                  f'native 使用表有 {n(len(usage))} 个 `(table, id)`，合计 {n(sum(int(row["call_sites"]) for row in usage))} 个调用位置。', '']

    bvm_summary = read_json(out / 'bvm-native' / 'summary.json')
    if bvm_summary:
        flat = [(f'`{key}`', value if not isinstance(value, dict) else json.dumps(value, ensure_ascii=False))
                for key, value in bvm_summary.items() if not key.endswith('sha256')]
        parts += ['## BVM native', '', table(('项目', '值'), flat), '']

    parts += ['## 限制', '',
              '伪代码是 Ghidra 推断：类型、控制流和函数边界需要对照汇编核对；没有 pdb，名称来自 RTTI、脚本绑定、'
              '指令模式和 `shared/` 标签。只经运行时计算或间接调用进入、且没有静态引用的函数可能仍未识别。', '']
    target = out / '验证.md'
    temporary = target.with_name(target.name + '.tmp')
    temporary.write_text('\n'.join(parts), encoding='utf-8', newline='\n')
    temporary.replace(target)
    return target
