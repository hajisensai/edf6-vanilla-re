English | [中文](README.md)

# How to write notes

One Markdown file per subsystem, with a file name in English using hyphens, such as `helicopter-input.md`. Suggested structure:

```
# <subsystem> (build steam-17055427)

## Conclusions
- 0x006543A0 VehicleHelicopterBase::UpdateInput: every frame writes the seat joystick into the veh+0x1540 input block.

## How it was confirmed
- Breakpoints / call relationships / string references / RTTI, written so that others can verify.

## Unresolved
```

- Write only your own descriptions and RVAs; do not paste pseudocode or assembly. If you really need to illustrate something, you may include a snippet of at most 10 lines that you **rewrote yourself**, and mark it as "rewritten" (lint rejects code blocks longer than 10 lines).
- Also add newly confirmed function names and fields to `shared/functions` and `shared/types`, and just reference them from the note.
