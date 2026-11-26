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

## 镜头步进、骨骼 pose 与交换链（2026-11-24 补充）

- 镜头步进 0x0118DF40 只在 0x011995A6 调用。它是 System_Update 的 tick 循环里每个视口的最后一个调用，排在各对象阶段（系统 vtable 的 +0x38 / +0x30 / +0x20 / +0x40 / +0x28 / +0x48）之后，所以在它之后读到的是这个 tick 的最终状态。镜头的世界矩阵在 cam+0x220（行依次是右、上、前、位置），视野在 +0x24，跟随的士兵在 [cam+0x360]。
- 渲染录制在 System_Update 开头、tick 步进之前：0x01198FA4 调 0x011978D0，各视口经 0x01197B50 调 0x0118DFF0，用 +0x220 和 +0x24 算视图矩阵。所以 n ≥ 1 帧画的是上一帧末的状态。
- 骨骼实例（SkeletonInstance）：pose 数组 [inst+0x30] 由 0x01100F10 在对象的 tick 更新里写。渲染线程直接读这块对象内存，录制时不拷贝。帧末栅栏 0x011A305A 每帧都等渲染线程做完。士兵的身体是 h+0x860 的 AnimationModel，基础实例在 h+0x900；武器各自是独立的模型（weapon+0xF30）。
- 交换链：0x0111B220 建，调用者是设备初始化 0x0111B77B 和改模式 0x0111C8EC。改模式是重建交换链，不调 ResizeBuffers。描述拷到栈 rsp+0x30 后，在 0x0111B340 调 IDXGIFactory::CreateSwapChain：rcx 是 renderer+0xF8 的工厂，rdx 是设备，r8 是描述，r9 是输出。原版是 blt 模型。Present 在渲染线程 0x01118B45 调用：flags 固定为 0（0x01118B39 的 xor r8d,r8d），SyncInterval 在 xmm0 的第 3 个 dword 里。

## 帧数为 0 的帧与按调用次数推进的状态（2026-11-24 补充）

- 主循环在 0x011A2FD8 把最终的 tick 数存进 [rsp+0xBC]（Application_Update 里的 [r14+4]）。这个值已经过 ≤ 3 的夹取，以及 0x011A2FAC 的 [rdi+9] 置位分支（那里 n 置 0、dt 清零）。在 0x011A2F4F / 0x011A2F6B 取的 tick 数是这两步之前的值，两者可能不同。原版不会出现 n = 0 而 dt > 0 的帧。
- 0x007B3010 Sound_SmoothVolume 每次调用把 +0x3C 向目标逼近 0.1，+0xD8 加 0.01，按调用次数推进，不按 dt。每帧调一次时，帧数越多淡入淡出越快。
- 0x02139B84 g_UpdateLoadPercent 由 0x011A3033 每帧写入，是 Update 用时占 60 Hz 一帧的百分比。LOD 裁剪 0x00134210 / 0x00136621 按 200–350 % 的阈值读它。
- Application+0x6C 由 0x00704E60 置 8，只在 n ≥ 1 的帧递减，到 0 时 0x0070596F 调 0x00077200 Input_StopRumbleAndRepoll（停震动、重新枚举输入设备）。
- 0x00705597 累加的 Application+0x68 在全模块内没有读者。0x007AF3E0 按时间推进。0x011A1CA0 只在调试开关下运行。

## 怎么确认的

- 调用关系：直接调用点用 edf6-all-forces `tools/edfre.py` 的 callers / xrefs 枚举，每个「唯一调用者」都是全模块扫描的结果。
- QPC 周期、SyncInterval 的来源、栅栏轮询：逐条读这几个函数确认。插件钩 0x011A33DF，在设备初始化后先 GetMaximumFrameLatency 再设 1，实机日志记为 `max frame latency 1 (was 3)`，确认原版用的是默认值 3。
- 封装布局：从 0x0007CDC0 的循环步长与界限、0x01182BC0 读写的偏移得出。插件按这个布局在 n = 0 帧清边沿。

## 未解决

- ActionSource +0x4D 的确切含义（置位时封装不更新），置信度 guess。
- 每帧对活动相机 vslot_3 的调用是否按 dt 推进。
- 几个 UI 类在 OnUpdate 里按调用次数自增的字段（HUiMissionResult +0x794、HUiLobby +0x9DC、HUiRoom +0x8B4、HUiRoomFixedPhrase +0x8F4、HUiRoomSetting +0x7EC、HUiOpening +0x10、UiNotice +0x28），读者未查。
