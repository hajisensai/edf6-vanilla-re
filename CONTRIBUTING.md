English | [简体中文](CONTRIBUTING.zh-CN.md)

# Contributing

This repository accepts two kinds of things: **generation tools** (which use your own legal copy of EDF6 to generate assembly, pseudocode and indexes locally) and **our own analysis results** (function names, global variable names, struct fields, comments, Chinese notes). Just open a PR with new findings.

## 1. What may and may not be committed

| May be committed | Reason |
| --- | --- |
| Tool code such as `*.py`, `*.ps1`, `ghidra_scripts/*.java` | The tools themselves contain no game content |
| TSV files under `shared/`: function names, signatures, global variable names, struct fields | These are our own analysis results, containing only addresses and names we chose |
| Chinese notes `shared/notes/*.md` | Our own descriptions; just cite RVAs |
| Tests, CI, documentation | — |

| Must not be committed | Reason |
| --- | --- |
| Assembly listings (`.asm`, disassembly text), Ghidra/IDA pseudocode (`.c`, long `FUN_…` output), P-code, `.sqlite` databases, Ghidra projects (`.gpr`, `.rep`, `.gzf`) | Mechanically generated from the game binaries; amounts to redistributing game code |
| Mission script bodies (AngelScript `.ac` / BVM `.bvm` and their decompiled text) | Game content |
| Unpacked CPK files, `.sgo`, models, textures, audio, the `EDF.dll` / `EDF6.exe` binaries | Game content |
| Large copies of the original string tables, dialogue, weapon tables | Game content |

`tools/lint_shared.py` blocks these automatically: by suffix (`.asm .sqlite .c .h .pcode .gzf .gpr .ac .as .bvm .cpk .sgo .dll .exe …`), by generator output names (`native-usage.tsv`, `provenance.json`, `<name>.cpk/` directories, and output table headers such as `files.tsv`), by single-file size (512 KiB by default), by binary content, by Ghidra output signatures (`undefined8`, `FUN_1800…`, `param_1`, `local_28` and the like, judged by density: either the whole file is dense enough, or any 30-line window is), by disassembly signatures (runs of "address + machine code" lines, or "address + mnemonic + operands" lines without machine code), and by code blocks longer than 10 lines in notes (including indented code blocks; an unclosed fence is reported as an error). On PRs, CI also checks every commit with `--history`, so files that were added midway and then deleted are blocked as well. When something is blocked, do not work around it; rewrite the content as your own conclusions.

> **These checks record provenance; they are not a security boundary.** `lint_shared.py` only catches accidental commits in common formats; the gate in `verify_install.py` (before generation it checks that the game files are a registered official build, and when `--allow-unofficial` lets it through, that is written into `provenance.json`) only records which files an output came from. Both can be bypassed deliberately, and neither can prove that some text was not copied from the game. Whether something may be committed is decided in the end by the rules in the tables above and by the reviewer's judgment.

Notes may include explanatory code snippets of **at most 10 lines**, which must be rewritten by yourself (give variables meaningful names, remove irrelevant parts) and marked "rewritten".

## 2. Directories and formats

```
shared/
  builds.tsv                 build identifier -> module, sha256, TimeDateStamp, base address, image size
  functions/EDF.dll.tsv      functions (one file per module, e.g. EDF6.exe.tsv)
  data/EDF.dll.tsv           global variables / tables / vtables
  types/<TypeName>.tsv       struct / class fields, one file per type
  notes/<subsystem>.md       Chinese notes
```

General rules (all TSV):

- UTF-8 without BOM, LF line endings, the file ends with a newline; tab-separated, **a cell cannot contain a tab or a newline**, with no leading or trailing spaces.
- The first non-comment line is the header and must match the one below exactly; lines starting with `#` and blank lines are ignored.
- Every row carries a `build` column. An address is always bound to a build: with a different game version, the same function is a new row.
- RVAs are always written as 8-digit uppercase hexadecimal: `0x00ABCDEF` (relative to the image base; `EDF+0x6519A0` is written `0x006519A0`, and `0x1806519A0` minus the base is likewise written `0x006519A0`).
- Insert new rows sorted by RVA / offset, to make the diff easier to review.

### builds.tsv

| Column | Content |
| --- | --- |
| `build` | Build identifier, lowercase letters, digits and hyphens. For the Steam version use `steam-<depot buildid>`, such as `steam-17055427` (the `buildid` in `steamapps/appmanifest_2291060.acf`) |
| `module` | `EDF.dll`, `EDF6.exe` |
| `sha256` | SHA-256 of the module file, lowercase |
| `timedatestamp` | PE header TimeDateStamp, `0x678CCB46` |
| `image_base` | PE preferred base address, 16 digits: `0x0000000180000000` |
| `size_of_image` | PE `SizeOfImage`, 8 digits; lint uses it to check the RVA range |
| `notes` | May be empty |

### functions/<module>.tsv

Columns: `build rva name signature confidence evidence notes`

- `name`: see section 3.
- `signature`: may be empty. When filled in, use a C prototype, such as `void __fastcall Foo::Update(Foo * this, float dt)`; the Ghidra import script tries to apply it, and failures are only logged.
- `confidence` / `evidence`: see sections 3 and 4.
- `notes`: may be empty; write the Chinese description here.

### data/<module>.tsv

Columns: `build rva name type confidence evidence notes`. `type` is free text (`float`, `Foo*`, `vtable`); a vtable is named `Class::vftable` (when the class name has RTTI evidence) or `Something_vftable`.

### types/<TypeName>.tsv

Columns: `build offset size name type confidence evidence notes`

- The file name is the type name (an ASCII identifier), such as `SoldierBase.tsv`.
- `offset`: uppercase hexadecimal, at least 4 digits: `0x0228`.
- `size`: decimal, `0x` hexadecimal, or `?` (unknown). Fields with a known size must not overlap.
- `type`: `u8 i8 u16 i16 u32 i32 int float double u64 i64 ptr Foo* vec4 float4 mat4 wchar_t* weak_ptr struct array ?` and so on; the Ghidra import script recognizes the basic types at the front, and builds the rest as undefined bytes according to `size`.
- `name`: field names are ASCII identifiers; copy SGO parameter names as they are (such as `AmmoCount`), and use snake_case for the others.

### notes/*.md

One file per subsystem, mainly in Chinese. State clearly "what it is, how it was confirmed, and which RVAs it relates to". Write addresses as `0x00ABCDEF` and state the build (once at the start of the file is enough). Do not paste pseudocode, except rewritten snippets of at most 10 lines.

## 3. Naming and confidence

Naming rules:

- When the class name has evidence (RTTI, vtable, a class name in a string, upstream source), use C++ style `Class::Method`, writing namespaces as they are: `mission_script::GlobalFunctions::GlobalFunctions`; write destructors as `Class::~Class` and vtables as `Class::vftable`.
- When the class name is not confirmed, use `Subsystem_Action` with a PascalCase prefix: `Havok_Body_GetMass`, `Script_SetMoveArea`, `DropItemManager_Unit_vftable`. Do not invent class names.
- For a method known only from its vtable slot, include the slot: `VehicleHelicopterBase::Init_Slot46`.
- Distinguish overloads of the same name with a suffix: `GameDamageInfo_ApplyAreaDamage_GdiRadius`. Names must be unique within the same build.
- Use only ASCII letters, digits, underscores and `::`. **Chinese names cannot go in the `name` column**; put them in `notes`.
- Auto-generated placeholder names such as `sub_…`, `FUN_…`, `DAT_…`, `vslot_N` are **not entered into the tables**: if you do not know what something is, do not add the row.

Confidence:

| Value | Meaning |
| --- | --- |
| `confirmed` | Direct, reproducible evidence: an RTTI class name, an AngelScript / script registration name, a uniquely referenced string, or a point-by-point match with upstream source (such as AngelScript 2.28.2 or the public Havok headers) |
| `likely` | The behavior was checked with live breakpoints / logs / call relationships, and the name was chosen from the behavior |
| `guess` | There are leads but they are unchecked. Allowed in the tables, but others may change it directly when they have better evidence |

## 4. Evidence requirements

The `evidence` column is required. State in one sentence how you know, so that others can verify it:

- `RTTI .?AVhknpWorld@@; vtable 0x018BC9C0 slot 54`
- `string ref "SetMoveArea( not found : %ls )"`
- `AngelScript registration "void SetMoveArea(...)" at 0x001E838E`
- `breakpoint: hit once per frame while driving, RCX=vehicle` (live breakpoint)
- `upstream source match: AngelScript 2.28.2 as_context.cpp`
- When citing the plugin project's notes, write the file name: `edf6-all-forces docs/heli-input-re.md: vtable slot 55`

Reasons that cannot be verified, such as "guessed from the pseudocode", are not acceptable; also do not paste pseudocode into evidence.

## 5. How to migrate addresses when a new build comes out

1. Add a new build row to `builds.tsv` (compute the sha256 with `python -c` or any tool, and copy the PE header fields), and in the same PR add the matching module rows to the root `known-builds.tsv`. `verify_install.py` judges a PE official only by the SHA-256 in `known-builds.tsv`: a new build that is not registered is judged "new Steam build, unregistered" (exit code 3) even if it matches the Steam manifest, and until it is registered you can only generate with `--allow-unofficial`.
2. **Always keep the rows of old builds**, without changing or deleting them; players on old versions and old notes still need them.
3. For each function to be migrated, relocate it in the new image by a byte signature: take 16–32 bytes from the old function entry, replace the bytes that contain absolute addresses / RIP-relative displacements / call targets with wildcards, and search the executable sections of the new image; only a **unique hit** counts as a successful relocation. You can also reconfirm using call relationships (call targets in known callers) or string references.
4. The new row gets the RVA of the new build, `evidence` reads `migrated from steam-17055427 0x006519A0 by byte signature (unique)`, and the confidence must not be higher than the old row's; if the signature has multiple hits or needs manual judgment, lower it to `guess`.
5. Run `python tools/lint_shared.py --game <new game directory>` and confirm that all new addresses fall on function entries in executable sections.

## 6. PR workflow

1. Before submitting, run:

   ```
   python tools/lint_shared.py                    # format + output guard
   python tools/lint_shared.py --game "<game directory>"  # when you have the game, also check that RVAs land on function entries
   python -m unittest discover -s tests
   ```

   CI runs only the checks that do not need the game files; `--game` can only be run locally, so write the result in the PR description.
2. **One PR covers only one subsystem** (for example "helicopter input" or "drop items"), to make review and rollback easier.
3. When you change a name, type or confidence that someone else already added, write the reason and the new evidence in the PR description, and put the old name in `notes` (`别名: old name`, i.e. "alias: old name") to make it searchable.
4. Mark uncertain conclusions as `guess`; do not raise the confidence just to look better.
5. Do not commit anything from `out/` (it is already in `.gitignore`).

## 7. How it connects to the tools

- `ghidra_scripts/ImportSharedLabels.java`: imports `shared/` into a Ghidra project headlessly; it picks the build by the sha256 in `builds.tsv`, creates functions, renames them and writes plate comments at image base + RVA (the `[shared-labels]` block records confidence and evidence), and can optionally import `types/` as structs under the `/shared` category. On a conflict the shared tables win and a log entry is written.

  ```
  analyzeHeadless <project_dir> <project> -process EDF.dll -noanalysis \
      -scriptPath ghidra_scripts -postScript ImportSharedLabels.java <repo>/shared types
  ```

## 8. License

The tool code and the `shared/` data are both under the MIT license (see [LICENSE](LICENSE)). The third-party code bundled in `edf6re_lib/` keeps its original license (such as `edf6re_lib/LICENSE.edf6-cpk`). By submitting, you agree to publish your contribution under the licenses above.