# 主循环、呈现与每帧输入（build steam-17055427）

## 结论

- 0x011DAE60 MainLoop_CountTicks：主循环的 tick 门。用 QPC 计时，周期是 freq*100/5994，即 59.94 Hz。返回自上次以来过去了几个 tick，只由 0x011A2F4F 和 0x011A2F6B 调用。调用方把 n 夹到 3 以内，然后调 0x00705530 Application_Update，参数是 {dt, n}。
- 每帧的输入顺序：
  1. 0x011A2FF3 把原始输入采样进动作源。
  2. 0x00705715 调 0x01198DA0 System_Update，先渲染、再按 n 步进，步进读的是动作封装。
  3. 0x007058C7 调 0x00077320 InputManager_UpdateActionWrappers，经 0x0007CDC0 逐个调 0x01182BC0 ActionWrapper_Update。

  结果是这一帧采到的输入要到下一帧的步进才被看到。帧率高于 tick 率时，n = 0 帧的封装更新会把上一帧设好的边沿清掉，步进来不及看到。
- 动作封装表在 g_InputManager（0x020B28A0）的 +0x5AE8：4 名玩家，每人 0xDD0 字节，从 +8 起是 146 个 ActionWrapper，每个 0x18 字节。之后是这名玩家菜单键的位掩码：+0xDB8 按住、+0xDBC 按下、+0xDC0 重复、+0xDC4 松开。字段见 `shared/types/ActionWrapper.tsv`、`ActionSource.tsv`。
- 鼠标位移和滚轮在采样时被取走：
  - 0x011831F0 Input_TakeMouseDelta 拷出 0x01FEEE20，再重置为 0x01765B30 的值。
  - 0x011832D0 Input_TakeWheel 取走 0x021360C0 并清零。
  - 两处都在 0x01188479 / 0x01188480，每帧取一次。
- 0x00705530 Application_Update 每帧推进一次共享随机数 0x01F54128（LCG），不论 n 是多少。
- SyncInterval：0x011A3095 取 `[rdi+0xC] == 0` 作为 SyncInterval。`[rdi+0xC]` 每帧减 1，n > 1（追帧）时置 8。所以平时 SyncInterval 恒为 1，追帧后 8 帧为 0。值经 0x011A309B 传给 0x0111D890 Renderer_QueuePresent（它的唯一调用点），渲染线程在 0x01118B45 调 Present(SyncInterval, 0)。游戏里没有对应的设置项。
- 0x0111CC20 Renderer_WaitGpuFence 是忙等：每次新建一个自动复位事件（0x00050D10），录一条 signal 命令，再用 0x00050E00（WaitForSingleObject 超时 0）加 Sleep(0) 轮询到事件置位。超过 1 s 后才顺带处理窗口消息。
- 0x0111B420 Renderer_InitDevice（唯一调用者 0x011A33DF，参数 g_Renderer 0x02136FF0）：设备存在 renderer+0x80，交换链在 +0x90。它只为 GetAdapter 查询 IDXGIDevice1，从不调 SetMaximumFrameLatency，所以 DXGI 排队帧数是系统默认的 3。

## 怎么确认的

- 调用关系：直接调用点用 edf6-all-forces `tools/edfre.py` 的 callers / xrefs 枚举，每个「唯一调用者」都是全模块扫描的结果。
- QPC 周期、SyncInterval 的来源、栅栏轮询：逐条读这几个函数确认。插件钩 0x011A33DF，在设备初始化后先 GetMaximumFrameLatency 再设 1，实机日志记为 `max frame latency 1 (was 3)`，确认原版用的是默认值 3。
- 封装布局：从 0x0007CDC0 的循环步长与界限、0x01182BC0 读写的偏移得出。插件按这个布局在 n = 0 帧清边沿。

## 未解决

- ActionSource +0x4D 的确切含义（置位时封装不更新），置信度 guess。
- 每帧对活动相机 vslot_3 的调用、各 UI 界面的内部推进，是否都按 dt 推进。
