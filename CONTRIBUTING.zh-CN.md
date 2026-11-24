[English](CONTRIBUTING.md) | 简体中文

# 参与贡献 / Contributing

本仓库收两样东西：**生成工具**（用你自己的正版 EDF6 在本机生成汇编、伪代码、索引）和**我们自己的分析结论**（函数名、全局变量名、结构体字段、注释、中文笔记）。新发现直接开 PR。

> This repository accepts tools and our own analysis (names, fields, comments, notes). It never accepts anything generated from or copied out of the game files. Everyone generates those locally from their own legal copy.

## 1. 能提交什么 / 不能提交什么

| 可以提交 | 原因 |
| --- | --- |
| `*.py`、`*.ps1`、`ghidra_scripts/*.java` 等工具代码 | 工具本身不含游戏内容 |
| `shared/` 下的 TSV：函数名、签名、全局变量名、结构体字段 | 这是我们自己的分析结论，只含地址和自己起的名字 |
| `shared/notes/*.md` 中文笔记 | 自己的描述；引用 RVA 即可 |
| 测试、CI、文档 | — |

| 禁止提交 | 原因 |
| --- | --- |
| 汇编清单（`.asm`、反汇编文本）、Ghidra/IDA 伪代码（`.c`、`FUN_…` 成段输出）、P-code、`.sqlite` 数据库、Ghidra 项目（`.gpr`、`.rep`、`.gzf`） | 由游戏二进制机械生成，等于再分发游戏代码 |
| 任务脚本正文（AngelScript `.ac` / BVM `.bvm` 及其反编译文本） | 游戏内容 |
| CPK 解包文件、`.sgo`、模型、贴图、音频、`EDF.dll` / `EDF6.exe` 本体 | 游戏内容 |
| 大段拷贝的原版字符串表、对白、武器表 | 游戏内容 |

> Never commit disassembly, decompiler output, P-code, SQLite databases, Ghidra projects, mission script bodies, unpacked CPK files, game binaries or large copies of game strings.

`tools/lint_shared.py` 会自动拦截这些文件：按后缀（`.asm .sqlite .c .h .pcode .gzf .gpr .ac .as .bvm .cpk .sgo .dll .exe …`）、生成器的产物名（`native-usage.tsv`、`provenance.json`、`<名字>.cpk/` 目录、`files.tsv` 等产物表头）、单文件大小（默认 512 KiB）、二进制内容、Ghidra 输出特征（`undefined8`、`FUN_1800…`、`param_1`、`local_28` 等按密度判定：整份文件够密，或任意 30 行窗口里够密）、反汇编特征（成片「地址 + 机器码」行，或不带机器码的「地址 + 助记符 + 操作数」行），以及笔记里超过 10 行的代码块（含缩进代码块；未闭合的围栏直接报错）。PR 上 CI 还会用 `--history` 逐个提交检查，中途加入又删掉的文件同样拦下。被拦下时不要绕过，把内容改写成自己的结论。

> **这些检查是来源记录，不是安全边界。** `lint_shared.py` 只能挡住常见格式的误提交；`verify_install.py` 的闸门（生成前核对游戏文件是否为已登记的官方构建，`--allow-unofficial` 放行时写进 `provenance.json`）只记录产物来自哪一份文件。两者都可以被刻意绕过，也不能证明某段文字没有抄自游戏。是否可以提交，最终以上表的规则和审查者的判断为准。
>
> These checks record provenance; they are not a security boundary. They catch common accidental commits and record which files an output came from, but they can be bypassed and cannot prove that text was not copied from the game. The rules above and review decide what may be committed.

笔记里允许 **≤10 行** 的说明性代码片段，必须是自己改写的（变量起有意义的名字、删掉无关部分），并注明「改写」。

## 2. 目录与格式

```
shared/
  builds.tsv                 build 标识 → 模块、sha256、TimeDateStamp、基址、镜像大小
  functions/EDF.dll.tsv      函数（每个模块一个文件，如 EDF6.exe.tsv）
  data/EDF.dll.tsv           全局变量 / 表 / vtable
  types/<TypeName>.tsv       结构体 / 类字段，一个类型一个文件
  notes/<子系统>.md          中文笔记
```

通用规则（所有 TSV）：

- UTF-8 无 BOM，LF 换行，文件以换行结尾；制表符分隔，**单元格里不能有制表符或换行**，首尾不留空格。
- 第一行非注释行是表头，必须与下文完全一致；`#` 开头的行和空行会被忽略。
- 每一行都带 `build` 列。地址永远绑定 build：换了游戏版本，同一个函数是一行新数据。
- RVA 一律写 8 位大写十六进制：`0x00ABCDEF`（相对镜像基址；`EDF+0x6519A0` 写成 `0x006519A0`，`0x1806519A0` 减去基址后同样写成 `0x006519A0`）。
- 新增行按 RVA / offset 排序插入，方便审查 diff。

### builds.tsv

| 列 | 内容 |
| --- | --- |
| `build` | build 标识，小写字母数字和连字符。Steam 版用 `steam-<depot buildid>`，如 `steam-17055427`（`steamapps/appmanifest_2291060.acf` 里的 `buildid`） |
| `module` | `EDF.dll`、`EDF6.exe` |
| `sha256` | 模块文件的 SHA-256，小写 |
| `timedatestamp` | PE 头 TimeDateStamp，`0x678CCB46` |
| `image_base` | PE 首选基址，16 位：`0x0000000180000000` |
| `size_of_image` | PE `SizeOfImage`，8 位；lint 用它检查 RVA 范围 |
| `notes` | 可空 |

### functions/<module>.tsv

列：`build rva name signature confidence evidence notes`

- `name`：见第 3 节。
- `signature`：可空。填写时用 C 原型，如 `void __fastcall Foo::Update(Foo * this, float dt)`；Ghidra 导入脚本会尝试应用，失败只记日志。
- `confidence` / `evidence`：见第 3、4 节。
- `notes`：可空，中文说明写在这里。

### data/<module>.tsv

列：`build rva name type confidence evidence notes`。`type` 写自由文本（`float`、`Foo*`、`vtable`）；vtable 命名为 `Class::vftable`（类名有 RTTI 证据时）或 `Something_vftable`。

### types/<TypeName>.tsv

列：`build offset size name type confidence evidence notes`

- 文件名就是类型名（ASCII 标识符），如 `SoldierBase.tsv`。
- `offset`：大写十六进制，至少 4 位：`0x0228`。
- `size`：十进制、`0x` 十六进制或 `?`（不知道）。已知大小的字段不能重叠。
- `type`：`u8 i8 u16 i16 u32 i32 int float double u64 i64 ptr Foo* vec4 float4 mat4 wchar_t* weak_ptr struct array ?` 等；Ghidra 导入脚本认识前面这些基础类型，其余按 `size` 建成未定义字节。
- `name`：字段名用 ASCII 标识符；SGO 参数名照抄（如 `AmmoCount`），其余用 snake_case。

### notes/*.md

一个子系统一篇，中文为主。写清楚「是什么、怎么确认的、和哪些 RVA 有关」。引用地址用 `0x00ABCDEF` 并注明 build（文件开头写一次即可）。不贴伪代码，≤10 行的改写片段除外。

## 3. 命名与置信度

命名规则 / Naming:

- 类名有证据（RTTI、vtable、字符串里的类名、上游源码）时用 C++ 风格 `Class::Method`，命名空间照写：`mission_script::GlobalFunctions::GlobalFunctions`，析构写 `Class::~Class`，vtable 写 `Class::vftable`。
- 类名没证实时用 `子系统_动作`，PascalCase 前缀：`Havok_Body_GetMass`、`Script_SetMoveArea`、`DropItemManager_Unit_vftable`。不要编造类名。
- 只按 vtable 槽位知道的方法，带上槽位：`VehicleHelicopterBase::Init_Slot46`。
- 同名重载加后缀区分：`GameDamageInfo_ApplyAreaDamage_GdiRadius`。同一 build 内名字必须唯一。
- 只用 ASCII 字母、数字、下划线和 `::`。**中文名不能进 `name` 列**，写进 `notes`。
- `sub_…`、`FUN_…`、`DAT_…`、`vslot_N` 这类自动生成的占位名**不入表**：不知道是什么就不要加这一行。

置信度 / Confidence:

| 取值 | 含义 |
| --- | --- |
| `confirmed` | 有直接、可复现的证据：RTTI 类名、AngelScript / 脚本注册名、引用的唯一字符串、与上游源码（如 AngelScript 2.28.2、Havok 公开头文件）逐条对照一致 |
| `likely` | 行为已用实机断点 / 日志 / 调用关系核对过，名字是按行为起的 |
| `guess` | 有线索但没核对。允许入表，但别人有更好的证据时可以直接改 |

## 4. 证据要求 / Evidence

`evidence` 列必填，一句话说清怎么知道的，能让别人复核：

- `RTTI .?AVhknpWorld@@; vtable 0x018BC9C0 slot 54`
- `string ref "SetMoveArea( not found : %ls )"`
- `AngelScript registration "void SetMoveArea(...)" at 0x001E838E`
- `breakpoint: hit once per frame while driving, RCX=vehicle`（实机断点）
- `upstream source match: AngelScript 2.28.2 as_context.cpp`
- 引用插件项目笔记时写文件名：`edf6-all-forces docs/heli-input-re.md: vtable slot 55`

不能写「看伪代码猜的」这种无法复核的理由；也不要把伪代码贴进 evidence。

## 5. 新 build 出来时怎么迁移地址

1. 在 `builds.tsv` 加一行新 build（`python -c` 或任意工具算 sha256，PE 头字段照抄），同一个 PR 里在根目录 `known-builds.tsv` 加对应的模块行。`verify_install.py` 判 PE 官方只认 `known-builds.tsv` 的 SHA-256：没登记的新构建即使与 Steam 清单一致，也会判为「Steam 新构建，未登记」（退出码 3），登记前只能用 `--allow-unofficial` 生成。
2. **旧 build 的行一律保留**，不改不删；老版本玩家和旧笔记还要用。
3. 对每个要迁移的函数，用字节签名在新镜像里重新定位：从旧函数入口取 16–32 字节，把含绝对地址 / RIP 相对位移 / call 目标的字节换成通配符，在新镜像的可执行节里搜索；**唯一命中**才算定位成功。也可以借助调用关系（已知调用者里的 call 目标）或字符串引用重新确认。
4. 新行写新 build 的 RVA，`evidence` 写 `migrated from steam-17055427 0x006519A0 by byte signature (unique)`，置信度不能高于旧行；签名有多处命中或需要人工判断的降为 `guess`。
5. 跑 `python tools/lint_shared.py --game <新版游戏目录>`，确认新地址都落在可执行节的函数入口上。

> When a new game build ships, add a `builds.tsv` row, keep every old row, relocate each function by a wildcarded byte signature (unique hit only), and add new rows citing the old build and RVA as evidence.

## 6. PR 流程

1. 提交前跑：

   ```
   python tools/lint_shared.py                    # 格式 + 产物守卫
   python tools/lint_shared.py --game "<游戏目录>"  # 有游戏时再核对 RVA 落在函数入口
   python -m unittest discover -s tests
   ```

   CI 只跑不需要游戏文件的检查；`--game` 只能在本机跑，PR 描述里写上结果。
2. **一个 PR 只做一个子系统**（例如「直升机输入」「掉落物」），方便审查和回滚。
3. 改别人已有的名字、类型或置信度时，在 PR 描述里写理由和新证据；把旧名字写进 `notes`（`别名: 旧名`），方便搜索。
4. 不确定的结论标 `guess`，不要为了好看抬高置信度。
5. 不要提交 `out/` 里的任何东西（已在 `.gitignore`）。

> One subsystem per PR. Run the lint and tests. Renaming someone else's entry requires a reason and evidence in the PR description.

## 7. 和工具的衔接

- `ghidra_scripts/ImportSharedLabels.java`：headless 把 `shared/` 导入 Ghidra 项目，按 `builds.tsv` 的 sha256 选 build，按镜像基址 + RVA 建函数、改名、写 plate comment（`[shared-labels]` 块里记置信度和证据），可选导入 `types/` 为 `/shared` 分类下的结构体。冲突时共享表优先并写日志。

  ```
  analyzeHeadless <project_dir> <project> -process EDF.dll -noanalysis \
      -scriptPath ghidra_scripts -postScript ImportSharedLabels.java <repo>/shared types
  ```

## 8. 许可

工具代码与 `shared/` 数据均按 MIT 许可（见 [LICENSE](LICENSE)）。`edf6re_lib/` 中内置的第三方代码沿用其原许可（如 `edf6re_lib/LICENSE.edf6-cpk`）。提交即表示你同意按上述许可发布你的贡献。

> Tools and `shared/` data are MIT-licensed; bundled code under `edf6re_lib/` keeps its original license. By contributing you agree to license your contribution under these terms.
