[English](README.en.md) | 中文

# 笔记写法

一个子系统一篇 Markdown，文件名用英文短横线，如 `helicopter-input.md`。建议结构：

```
# <子系统>（build steam-17055427）

## 结论
- 0x006543A0 VehicleHelicopterBase::UpdateInput：每帧把座位摇杆写进 veh+0x1540 输入块。

## 怎么确认的
- 断点 / 调用关系 / 字符串引用 / RTTI，写到别人能复核。

## 未解决
```

- 只写自己的描述和 RVA；不贴伪代码或汇编。确需说明时可以放 ≤10 行**自己改写**的片段，并注明「改写」（lint 会拒绝超过 10 行的代码块）。
- 新确认的函数名、字段同时补进 `shared/functions`、`shared/types`，笔记里引用它们即可。
