[English](README.md) | 简体中文

# shared/

协作者共享的分析数据：函数名、全局变量名、结构体字段和中文笔记。格式、命名、置信度与证据要求见 [CONTRIBUTING.md](../CONTRIBUTING.zh-CN.md)，提交前跑 `python tools/lint_shared.py`。

这里只放我们自己的结论（地址 + 自己起的名字 + 证据说明），不放任何由游戏文件生成的内容。

| 路径 | 内容 |
| --- | --- |
| `builds.tsv` | build 标识 → 模块、sha256、TimeDateStamp、基址、镜像大小 |
| `functions/<module>.tsv` | 函数 RVA → 名字、签名、置信度、证据 |
| `data/<module>.tsv` | 全局变量 / 表 / vtable RVA → 名字 |
| `types/<TypeName>.tsv` | 结构体 / 类字段 |
| `notes/*.md` | 按子系统写的中文笔记 |

初始种子（`steam-17055427`）来自两处：原 `function-labels.tsv` 的条目，以及插件项目 edf6-all-forces 的 `docs/*-re.md` 逆向笔记中写明依据的条目；`evidence` 列注明了来源笔记文件名。
