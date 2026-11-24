English | [中文](README.md)

# EDF6 Vanilla Code Research Tools (edf6-vanilla-re)

Generate a readable local mirror of the stock code of **your own** Steam copy of EARTH DEFENSE FORCE 6: line-by-line assembly, Ghidra C pseudocode, an RVA-indexed SQLite database, and an index of AngelScript / BVM mission scripts. It also comes with a shared set of function names, struct fields and notes that everyone maintains together.

## What this repository contains, and what it does not

- **Contains**: generation and query tools (Python / PowerShell / Ghidra scripts), and our own analysis results under `shared/`: function names, global variable names, struct fields and notes.
- **Does not contain**: anything generated from the game files, including assembly, pseudocode, P-code, databases, mission script bodies, unpacked resources, and the game itself. Everyone generates these locally from their own legal copy, and the output stays on their own machine (by default in `out/`, which is listed in `.gitignore`).

CI runs `tools/lint_shared.py` to block game-generated output. The full rules are in [CONTRIBUTING.en.md](CONTRIBUTING.en.md).

## First, confirm your game files are official

All addresses (RVAs) are bound to a specific game build. If you generate from files that someone else sent you, or that are patched, unpacked or from the Epic version, the addresses and code may not match, and submitting names based on them would pollute the shared data.

```powershell
python -B verify_install.py "D:/steam/steamapps/common/EARTH DEFENSE FORCE 6"
```

- It reads Steam's own depot manifests (`steamapps/appmanifest_2291060.acf` and `depotcache/*.manifest`) and checks the SHA1 of `EDF.dll`, `EDF6.exe` and the four CPK files one by one.
- If no Steam manifest can be found (for example, the directory was copied), it falls back to comparing against the SHA-256 values in [known-builds.tsv](known-builds.tsv).
- Exit codes: `0` is an official original, `2` is unofficial or modified, `3` is undetermined.
- Add `--quick` to check only the two PE files and skip the roughly 30 GB of CPK files.
- Third-party files such as CreamAPI, EDFModLoader and Mods are only listed as warnings and do not affect the verdict, because generation reads only the files listed above.

Every generation command that reads game files runs this check first. If it fails, generation is refused unless you add `--allow-unofficial` / `-AllowUnofficial`. If you add it, the output's `provenance.json` records that fact, and later query commands print a warning at the start.

The currently known official build is Steam buildid `17055427`: the TimeDateStamp of `EDF.dll` is `0x678CCB46`, and that of `EDF6.exe` is `0x678CCB63`.

## Environment

- Windows, Python 3.12+, then run `pip install -r requirements.txt` (pefile, capstone, unicorn).
- Generating pseudocode needs [Ghidra 12.1.3](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build) and JDK 21.
- Disk: the full output is about 1 GB (about 560 MB of DLL assembly, about 370 MB of database), and the Ghidra project needs about 2 GB more.

## Generation and queries

### Generate all output with one command

```powershell
python -B generate.py --game "D:/steam/steamapps/common/EARTH DEFENSE FORCE 6" --ghidra "D:/tools/ghidra_12.1.3_PUBLIC"
```

- It runs in order: database -> assembly -> Ghidra import and analysis -> main export -> `.pdata` supplementary scan -> timeout retry -> direct-call / vtable candidates -> AngelScript registration entries -> relocation / RIP pointer supplementary scan -> instruction-level P-code for two very large functions -> mission scripts -> BVM native -> function index -> `验证.md`.
- The address lists needed by the later Ghidra passes are computed automatically from `vanilla.sqlite` and the exports of the earlier passes, and are written to `out/addresses/<module>/`, so you do not need to prepare them by hand.
- AngelScript SDK 2.28.2 is downloaded from the official site into `out/_cache/` and used only after its SHA-256 is checked; it never enters the repository. If you have no network access, download it manually first and pass it with `--sdk <zip>`.
- A full run over both modules takes about 25 minutes (measured with 6 threads); most of that is Ghidra. Ghidra auto-analysis is capped at 430 seconds by default (`--analysis-timeout`), and every export pass is multi-threaded (`--workers`). Running only `EDF6.exe` takes under a minute.
- Common options:
  - `--out <dir>`: put the output elsewhere, for example on a larger drive.
  - `--java <java.exe>`: specify it when JDK 21 is not on PATH.
  - `--dry-run`: only print the command of each step without running it.

### Interrupting, resuming and running single steps

- After each step finishes, it writes a marker file `out/.steps/<step>[.<module>].done`, and logs go to `out/logs/`.
- When a step fails, the script prints the tail of the log and the command to continue with:
  - Add `--resume`: skip steps that are already done.
  - Add `--steps <from this step>`: rerun only from the failed step.
- Every step can be rerun on its own. Before rerunning, only that step's own output is cleared, and if a prerequisite step has not finished yet, it fails immediately and tells you which step to run first:

```powershell
python -B generate.py --game ... --ghidra ... --steps candidates,pointers   # recompute only candidate entries and the pointer supplementary scan
python -B generate.py --game ... --ghidra ... --module EDF6.exe             # process only EDF6.exe
python -B generate.py --help                                               # all steps and their descriptions
```

### Common queries

- `--module EDF.dll|EDF6.exe` goes **before** the subcommand, and defaults to `EDF.dll`.
- RVAs are in hexadecimal, and the `0x` prefix is optional.
- If the output is not in the default `out/`, first set the environment variable `$env:EDF6RE_OUT = "<output directory>"`.

```powershell
python -B vanilla.py show 1E31F0                  # assembly of the .pdata function containing this address, with > marking the address; --from-rva starts from that address
python -B vanilla.py c 1E31F0                     # Ghidra C pseudocode, found automatically across the export passes
python -B vanilla.py refs 1E31F0                  # who references this address; --outgoing what this instruction references, --function what the whole function references
python -B vanilla.py find CPP_OnBoot              # search symbols, RTTI class names, AngelScript registrations and notes for text
python -B vanilla.py function Player              # look up the function index by name or RVA (including aliases)
python -B vanilla.py vtable <vtable RVA>          # look up the class name and slots of an RTTI vtable (find the vtable RVA first with find <class name>)
python -B vanilla.py bvm 0 12                     # look up the signature and parameters of a BVM native (table number, decimal ID)
python -B vanilla.py --module EDF6.exe c 1000     # query EDF6.exe
```

### Output directory (default `out/`, not committed)

| Path | Content |
| --- | --- |
| `vanilla.sqlite` | sections, `.pdata`, per-instruction rows, static references, RTTI vtables / slots, note addresses |
| `assembly/<module>.asm` | line-by-line assembly, with `.pdata` range markers |
| `pseudocode*/<module>/` | the Ghidra C exports of each pass: a `functions.tsv` index plus `part-NNNN.c` volumes |
| `addresses/<module>/` | automatically computed address lists for retry, candidates, AngelScript and pointers, with their basis |
| `angelscript/` | the AngelScript registration table, annotated assembly, and instruction-level P-code of the two timed-out functions |
| `missions/` | mission AC source, BVM disassembly listings and `native-usage.tsv` |
| `bvm-native/` | BVM native signatures, parameters and script-stack check results |
| `function-index/` | names, RVAs, code locations and aliases of all entries (`functions.tsv`, `aliases.tsv`) |
| `验证.md` | the verification results of this local run; all numbers are counted on the spot |
| `logs/`, `.steps/`, `_cache/` | logs, step markers, and the Ghidra project, SDK and intermediate files |

### Reliability and limitations

- The assembly and the database are compared byte by byte against the original PE (`vanilla.py verify`); this layer is exact.
- C pseudocode is inferred by Ghidra. Types, parameters, control flow and function boundaries can all be wrong, so check against the assembly from `show` before drawing conclusions.
- The game has no pdb. Names come from RTTI, AngelScript bindings, instruction patterns and the shared labels in `shared/`; the rest are address-based generated numbers.
- Indirect calls (virtual functions, function pointers) have no target in the static index; first find out the object's type, then use `vtable` to look up the corresponding slot.
- A function that can only be reached through a runtime-computed address and has no static reference may not be recognized at all.
- Two very large functions time out when decompiled as a whole, so only instruction-level P-code and annotated assembly are provided for them.

## Contributing

If you have a new finding, just open a PR: add a function name row in `shared/functions/EDF.dll.tsv`, fill in struct fields in `shared/types/`, or write a note in `shared/notes/`. Every row must state its evidence (RTTI, string reference, AngelScript registration name, live breakpoint, etc.) and its confidence. Before submitting, run:

```powershell
python -B tools/lint_shared.py --game "<your game directory>"
python -B -m unittest discover -s tests
```

Before exporting, `decompile.ps1` imports the names in `shared/` into Ghidra, so the names everyone adds appear directly in the pseudocode that everyone regenerates.

## License

The tool code and the `shared/` data are under the MIT license; see [LICENSE](LICENSE). The CPK / CRILAYLA parsing code bundled in `edf6re_lib/` keeps its original license (Unlicense, see `edf6re_lib/LICENSE.edf6-cpk`). This project is not affiliated with SANDLOT or D3 PUBLISHER.
