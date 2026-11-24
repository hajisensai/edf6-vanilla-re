# Umbra 可见性与渲染线程（build steam-17055427）

## 结论

**可见性的录制与执行**

- 游戏线程逐视口录制可见性命令，渲染线程执行。
  - 0x011978D0 System_RecordDraw 遍历 4 个视口槽，scope 画中画开着时翻倍。
  - 每个视口录 4 次：
    - 主视图：0x011B6AA0 Render_RecordMainVisibility。
    - 阴影 2 次：0x011B6F90 Render_RecordShadowVisibility，按阴影级联循环。
    - 远景 1 次：0x011B6770 Render_RecordFarVisibility。
  - 所以每视口每帧调用 4 次 processVisibility；没找到反射 pass。
- 0x011B5A70 Render_ExecuteUmbraVisibility / 0x011B5B30 Render_ExecuteUmbraVisibility_Far 是渲染线程上的命令执行器，**不做可见性计算**。
  - 它们先把录制好的视图块拷进延迟渲染系统，再调 umbra_sandlot 的 processVisibility(Camera, Commander)。
  - 远景版在调用前后保存并恢复一个全局标志。
- Umbra Camera 的视锥和相机矩阵，由游戏线程在 0x0118DFF0 SceneCamera_BuildProjection 里写入；绘制用的矩阵另走录制的描述符。

**Commander：Umbra 的输出怎么被消费**

- 0x011E2120 UmbraCommander_Command 是 Umbra 回调命令的分发函数，vtable 0x01AE5288 的槽 1：
  - cmd 0：开始。
  - cmd 1：画可见物。
  - cmd 2：读视图参数。
  - cmd 3：收集可见实例。
  - cmd 4：遮挡体深度 pass。
  - cmd 5：发遮挡查询。
  - cmd 6：取查询结果。
  - cmd 9：调试线。
- 可见实例是活的渲染节点指针，在同一次 processVisibility 里就被画掉。**没有能留到下一帧的可见集对象。**
- 该函数里有 9 处 immediate context Flush。

**umbra_sandlot.dll 的线程**

- 只有一个 worker 线程。导出的 initThreads 是空桩，不能多开 worker。
- 渲染线程在 processVisibility 里等 worker 交回遮挡查询的结果。采样时这段等待会被记在 0x011B5A70 名下，实际上是线程之间的握手，不是 CPU 计算。

## 怎么确认的

- 调用关系和录制流程，由反汇编和对 vtable 的交叉引用逐条核对。
- 实机采样：用 rip_sampler 每 15 ms 采一次栈，场景 M001 / RM015。
  - 旧构建里，渲染线程 42% 的时间停在 worker 等待上。
  - 新构建里降到 1–5%。
- 函数次数、命令号和可见实例的生命周期，在 edf6-all-forces 的 `docs/umbra-reuse-re.md` 有展开说明。

## 未解决

- 新旧构建之间 worker 等待为什么大幅减少，还没定位。
- 0-tick 帧复用可见性的评估结论是不做：收益太小，悬空指针和遮挡时序的风险高。
