# Resource cache: what a miss costs the caller (build steam-17055427)

[简体中文要点见末尾]

## Conclusions

- 0x00084E80 ResourceCache_GetOrLoad(cache, out, key): the get-or-load used by CreateObject (call at 0x011946DF,
  cache = the global object 0x020B28D0) and 38 other call sites. The key is a wstring path followed by a 32-bit hash at
  +0x20; `out` receives {entry, cache}.
- A miss reads the file in the calling thread. 0x00089360 is only the insert into the loaded tree; the read itself is the
  entry's reader at entry+0x68, made by the factory pointer 0x02005540 (CpkContentFileReader_Create 0x00073970 or
  FileReader_Create 0x00042C90, chosen at file system setup). Open (vtable slot 1) starts a dedicated thread for the
  read (Thread_Start 0x0003E5A0); Wait(0) (slot 2, call at 0x00085052) joins it with an infinite wait (Thread_Join
  0x0003E690). So every miss is one thread created, the whole file read, and the caller blocked until it ends. Parsing
  the bytes (models, textures) happens later in the caller, outside 0x00084E80.
- A hit on an entry still being read by another thread also blocks: ResourceCache_Find 0x0009C950 checks the pending
  tree (cache+0x10, lock cache+0x50) and takes the pending entry's own lock (0x0009C9F4), which the reading thread holds
  from 0x00084FB3 until its read is done (0x00085118).
- A missing file: the entry is dropped (0x000850CD, 0x000850EF) and `out` is set empty, which callers such as
  CreateObject treat as fatal.
- All three paths (hit, read, not found) end at 0x00085159; the frame does not change rsp between the prologue and the
  epilogue, so a call-site hook can pair the calls of one invocation by their return-address slot.

## How it was checked

- Static: call relations and import references (CreateThread / ResumeThread / WaitForSingleObject / CloseHandle) in the
  functions named above; RTTI of the two reader vtables (0x0175F210, 0x0175F290).
- Live (edf6-all-forces src/sync_load_probe.cpp, 2026-11-24): call-site hooks at 0x00084ECF (the first lookup),
  0x00084FDA (the miss), 0x000850CD (not found) and 0x0008515D (the exit), timed on the game thread only; misses on the
  game thread were logged with their paths and durations during stock missions.

## Open questions

- Which callers run on the loader thread versus the game thread for each resource type is not mapped exhaustively.

## 要点（中文）

- `0x84E80` 未命中时在调用线程里起一个线程读整个文件并无限等待它结束；`0x89360` 只是插入已完成表。
- 命中「在读」条目时，查找 `0x9C950` 会等那个条目的锁，直到别的线程读完。
