## 子系统 / Subsystem

<!-- 一个 PR 只做一个子系统，例如「直升机输入」「掉落物」。One subsystem per PR. -->

## 改了什么 / What changed

- 新增：
- 修改（改了别人已有的名字 / 类型 / 置信度时，逐条写理由和新证据）：

## 证据 / Evidence

<!-- 关键条目怎么确认的：RTTI、字符串引用、脚本注册名、实机断点、上游源码对照等。不要贴伪代码或汇编。 -->

## 自查 / Checklist

- [ ] `python tools/lint_shared.py` 通过
- [ ] `python -m unittest discover -s tests` 通过
- [ ] 有游戏时跑过 `python tools/lint_shared.py --game "<游戏目录>"`（结果：）
- [ ] 没有提交汇编、伪代码、P-code、sqlite、任务脚本正文、CPK 解包文件或大段原版字符串
      (no disassembly, decompiler output, P-code, databases, mission scripts, CPK contents or copied game strings)
- [ ] 所有地址行都带 build，RVA 写成 `0x00ABCDEF`
- [ ] 新名字不是 `sub_` / `FUN_` 占位名，`name` 列没有中文
