English | [简体中文](README.zh-CN.md)

# shared/

Shared analysis data from collaborators: function names, global variable names, struct fields and Chinese notes. For format, naming, confidence and evidence requirements see [CONTRIBUTING.md](../CONTRIBUTING.md), and run `python tools/lint_shared.py` before submitting.

Only our own conclusions go here (address + a name we chose + an evidence description). Nothing generated from the game files belongs here.

| Path | Content |
| --- | --- |
| `builds.tsv` | build identifier -> module, sha256, TimeDateStamp, base address, image size |
| `functions/<module>.tsv` | function RVA -> name, signature, confidence, evidence |
| `data/<module>.tsv` | global variable / table / vtable RVA -> name |
| `types/<TypeName>.tsv` | struct / class fields |
| `notes/*.md` | Chinese notes written per subsystem |

The initial seed (`steam-17055427`) comes from two sources: the entries of the original `function-labels.tsv`, and the entries with stated evidence from the `docs/*-re.md` reverse-engineering notes of the plugin project edf6-all-forces; the `evidence` column records the source note file name.
