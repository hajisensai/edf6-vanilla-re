# EDF6 原版代码研究工具（edf6-vanilla-re）

用**你自己的** Steam 版《地球防卫军 6》（EARTH DEFENSE FORCE 6）在本机生成原版代码的可读镜像：逐行汇编、Ghidra C 伪代码、按 RVA 查询的 SQLite 索引、AngelScript / BVM 任务脚本索引。另有一套大家共同维护的函数名、结构体字段和中文笔记。

> Tools to generate a local, RVA-indexed mirror of EDF6's stock code from **your own** Steam install, plus a shared, PR-driven database of function names, struct fields and notes.

## 这个仓库放什么、不放什么

- **放**：生成工具和查询工具（Python / PowerShell / Ghidra 脚本），以及 `shared/` 下我们自己的分析结论：函数名、全局变量名、结构体字段和笔记。
- **不放**：任何由游戏文件生成的东西，包括汇编、伪代码、P-code、数据库、任务脚本正文、解包资源，以及游戏本体。这些都由每个人用自己的正版在本机生成，产物只留在自己电脑上（默认在 `out/`，已加进 `.gitignore`）。

CI 会运行 `tools/lint_shared.py`，拦截游戏产物。完整规则见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 先确认你的游戏文件是正版

所有地址（RVA）都绑定在具体的游戏构建上。用别人发的、打过补丁的、脱过壳的或 Epic 版的文件生成出来，地址和代码都可能对不上，拿这样的结果提交名字会污染共享数据。

```powershell
python -B verify_install.py "D:/steam/steamapps/common/EARTH DEFENSE FORCE 6"
```

- 它读取 Steam 自己的 depot 清单（`steamapps/appmanifest_2291060.acf` 和 `depotcache/*.manifest`），逐个核对 `EDF.dll`、`EDF6.exe` 和四个 CPK 的 SHA1。
- 找不到 Steam 清单时（比如目录是拷来的），退回去比对 [known-builds.tsv](known-builds.tsv) 里的 SHA-256。
- 退出码：`0` 是官方原版，`2` 是非官方或被改过，`3` 是无法判定。
- 加 `--quick` 只核两个 PE，跳过约 30 GB 的 CPK。
- CreamAPI、EDFModLoader、Mods 之类的第三方文件只会被列出来警告，不影响判定，因为生成只读上面那几个文件。

每个读游戏文件的生成命令都会先自动做这项核对。不通过就拒绝生成，除非加 `--allow-unofficial` / `-AllowUnofficial`；加了的话，产物的 `provenance.json` 里会记下这一点，之后的查询命令也会在开头警告。

当前已知的正版构建是 Steam buildid `17055427`：`EDF.dll` 的 TimeDateStamp 为 `0x678CCB46`，`EDF6.exe` 为 `0x678CCB63`。

## 环境

- Windows，Python 3.12+，执行 `pip install -r requirements.txt`（pefile、capstone、unicorn）。
- 生成伪代码需要 [Ghidra 12.1.3](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build) 和 JDK 21。
- 磁盘：完整产物约 1 GB（DLL 汇编约 560 MB，数据库约 370 MB），Ghidra 项目另需约 2 GB。

## 生成与查询

### 一条命令生成全部产物

```powershell
python -B generate.py --game "D:/steam/steamapps/common/EARTH DEFENSE FORCE 6" --ghidra "D:/tools/ghidra_12.1.3_PUBLIC"
```

- 依次执行：数据库 → 汇编 → Ghidra 导入分析 → 主导出 → `.pdata` 补扫 → 超时重试 → 直接调用 / 虚表候选 → AngelScript 注册入口 → 重定位 / RIP 指针补扫 → 两个超大函数的逐指令 P-code → 任务脚本 → BVM native → 函数总表 → `验证.md`。
- 后几轮 Ghidra 要用的地址清单由 `vanilla.sqlite` 和前几轮的导出自动算出，写在 `out/addresses/<模块>/`，不用手工整理。
- AngelScript SDK 2.28.2 从官网下载到 `out/_cache/`，核对 SHA-256 后才使用，不会进仓库。没网时先手动下载，再用 `--sdk <zip>` 指定。
- 两个模块完整跑一遍约 25 分钟（6 线程实测），大头是 Ghidra：Ghidra 自动分析默认 430 秒封顶（`--analysis-timeout`），各轮导出都是多线程（`--workers`）。只跑 `EDF6.exe` 不到一分钟。
- 常用参数：
  - `--out <目录>`：产物放到别处，例如空间更大的盘。
  - `--java <java.exe>`：PATH 上没有 JDK 21 时指定。
  - `--dry-run`：只打印每一步要执行的命令，不执行。

### 中断、续跑与单步

- 每步做完会写标记文件 `out/.steps/<步骤>[.<模块>].done`，日志在 `out/logs/`。
- 某步失败时，脚本会打印日志尾部，以及继续用的命令：
  - 加 `--resume`：跳过已经完成的步骤。
  - 加 `--steps <从这步起>`：只从失败的那一步重跑。
- 每一步都能单独重跑。重跑前只清掉这一步自己的输出，前置步骤还没完成时会直接报错并提示先跑哪一步：

```powershell
python -B generate.py --game ... --ghidra ... --steps candidates,pointers   # 只重算候选入口和指针补扫
python -B generate.py --game ... --ghidra ... --module EDF6.exe             # 只处理 EDF6.exe
python -B generate.py --help                                               # 全部步骤及其说明
```

### 常用查询

- `--module EDF.dll|EDF6.exe` 写在子命令**前面**，默认 `EDF.dll`。
- RVA 用十六进制，可以不带 `0x`。
- 产物不在默认的 `out/` 时，先设置环境变量 `$env:EDF6RE_OUT = "<产物目录>"`。

```powershell
python -B vanilla.py show 1E31F0                  # 所在 .pdata 函数的汇编，> 标出该地址；--from-rva 从该地址起
python -B vanilla.py c 1E31F0                     # Ghidra C 伪代码，会在各轮导出里自动查找
python -B vanilla.py refs 1E31F0                  # 谁引用了这个地址；--outgoing 该指令引用了什么，--function 整个函数引用了什么
python -B vanilla.py find CPP_OnBoot              # 在符号、RTTI 类名、AngelScript 注册和笔记里搜索文本
python -B vanilla.py function Player              # 按名称或 RVA 查函数总表（含别名）
python -B vanilla.py vtable <虚表RVA>             # 查 RTTI 虚表的类名和各个槽位（虚表 RVA 可先用 find 类名查到）
python -B vanilla.py bvm 0 12                     # 查 BVM native（表号、十进制 ID）的签名和参数
python -B vanilla.py --module EDF6.exe c 1000     # 查 EDF6.exe
```

### 输出目录（默认 `out/`，不入库）

| 路径 | 内容 |
| --- | --- |
| `vanilla.sqlite` | 节、`.pdata`、逐条指令、静态引用、RTTI 虚表 / 槽位、笔记地址 |
| `assembly/<模块>.asm` | 逐行汇编，含 `.pdata` 区间标记 |
| `pseudocode*/<模块>/` | 各轮 Ghidra C 导出：`functions.tsv` 索引加 `part-NNNN.c` 分卷 |
| `addresses/<模块>/` | 自动算出的重试、候选、AngelScript、指针地址清单及其依据 |
| `angelscript/` | AngelScript 注册表、注释汇编和两个超时函数的逐指令 P-code |
| `missions/` | 任务 AC 源码、BVM 反汇编清单和 `native-usage.tsv` |
| `bvm-native/` | BVM native 的签名、参数和脚本栈检查结果 |
| `function-index/` | 所有入口的名称、RVA、代码位置和别名（`functions.tsv`、`aliases.tsv`） |
| `验证.md` | 本机这次生成的核对结果，所有数字都是现场统计 |
| `logs/`、`.steps/`、`_cache/` | 日志、步骤标记，以及 Ghidra 项目、SDK 和中间文件 |

### 可靠性与限制

- 汇编和数据库逐字节对照原始 PE（`vanilla.py verify`），这一层是精确的。
- C 伪代码是 Ghidra 推断出来的。类型、参数、控制流和函数边界都可能不对，要下结论时请对照 `show` 的汇编核对。
- 游戏没有 pdb。名称来自 RTTI、AngelScript 绑定、指令模式和 `shared/` 里的共享标签，其余是按地址生成的编号。
- 间接调用（虚函数、函数指针）在静态索引里查不到目标，要先知道对象的类型，再用 `vtable` 查对应的槽位。
- 函数如果只能经运行时计算出的地址到达、又没有任何静态引用，可能完全没被识别出来。
- 有两个超大函数在整函数反编译时超时，只提供逐指令 P-code 和注释汇编。

## 参与贡献

有新发现就直接开 PR：在 `shared/functions/EDF.dll.tsv` 里加一行函数名，在 `shared/types/` 里补结构体字段，或者在 `shared/notes/` 里写笔记。每一行都要写上依据（RTTI、字符串引用、AngelScript 注册名、实机断点等）和置信度。提交前运行：

```powershell
python -B tools/lint_shared.py --game "<你的游戏目录>"
python -B -m unittest discover -s tests
```

`decompile.ps1` 在导出前会把 `shared/` 里的名字导入 Ghidra，所以大家补的名字会直接出现在每个人重新生成的伪代码里。

## 许可

工具代码和 `shared/` 数据采用 MIT 许可，见 [LICENSE](LICENSE)。`edf6re_lib/` 里内置的 CPK / CRILAYLA 解析代码沿用其原始许可（Unlicense，见 `edf6re_lib/LICENSE.edf6-cpk`）。本项目与 SANDLOT、D3 PUBLISHER 无关。
