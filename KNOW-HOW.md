# OpenClaw Risk Guard Know-How

这份文档记录了本项目从原型到可用版本的实现过程、关键架构、踩坑点和经验结论，方便后续继续演进。

## 目标

我们要做的是一层本地安全网关，挂在 OpenClaw 的工具调用前：

- 防 Prompt 注入
- 防越权外发和敏感信息泄露
- 对高风险副作用做用户确权
- 对操作结果做审计
- 保留接入阿里云 PAI / 千问蒸馏模型的演进空间

## 最终架构

### 1. OpenClaw 扩展层

入口文件：

- [.openclaw/extensions/openclaw-risk-guard/index.ts](/Users/fanjiang/Documents/riskops/.openclaw/extensions/openclaw-risk-guard/index.ts)

职责：

- 监听 `before_tool_call`
- 从 OpenClaw 事件中抽取工具名、参数、来源、会话信息
- 发送到本地风险服务 `/v1/evaluate`
- 按返回结果映射成：
  - 放行
  - 阻断
  - 原生 `requireApproval`

### 2. 风险服务层

入口：

- [main.py](/Users/fanjiang/Documents/riskops/main.py)
- [risk_guard/server.py](/Users/fanjiang/Documents/riskops/risk_guard/server.py)

职责：

- 提供 HTTP API
- 提供 Web UI
- 写审计
- 写审批状态
- 在 `confirm` 时发 macOS 桌面通知

### 3. 策略引擎

核心文件：

- [risk_guard/policy.py](/Users/fanjiang/Documents/riskops/risk_guard/policy.py)
- [config/policy.json](/Users/fanjiang/Documents/riskops/config/policy.json)

职责：

- 规则优先的风险判断
- 可选叠加 LLM 二判
- 生成更可读的审批文案

### 4. 审计与审批存储

核心文件：

- [risk_guard/store.py](/Users/fanjiang/Documents/riskops/risk_guard/store.py)
- [data/risk_guard.db](/Users/fanjiang/Documents/riskops/data/risk_guard.db)

职责：

- 持久化 `evaluations`
- 持久化 `approvals`
- 记录 `allow-always`
- 在展示层对 `web_search` 做 `query -> user_prompt` fallback

### 5. 调试与审计 UI

文件：

- [ui/index.html](/Users/fanjiang/Documents/riskops/ui/index.html)
- [ui/index.js](/Users/fanjiang/Documents/riskops/ui/index.js)
- [ui/index.css](/Users/fanjiang/Documents/riskops/ui/index.css)

职责：

- 策略编辑
- 手工评估
- 审计浏览
- 审批处理

## 实现过程回顾

### 阶段 1：先把最小可用链路跑通

最开始先做了一个本地 HTTP 风险服务，返回三态：

- `allow`
- `confirm`
- `block`

然后在 OpenClaw 扩展里用 `before_tool_call` 去调用它。

这一步验证了一个关键判断：

- OpenClaw 可以通过 Hook 实现“风险告知 + 用户确权”

### 阶段 2：补规则、审计和 Web UI

在最小链路可跑之后，补了：

- SQLite 审计
- `/v1/audit`
- `/v1/approvals`
- 在线策略编辑
- 手工调试判定

这一步把系统从“能判”推进到了“能查、能调、能回放”。

### 阶段 3：定位 OpenClaw 事件结构

这是最关键的调试阶段。

现象是：

- 审计里经常出现空记录
- `tool_name = ""`
- `source = "unknown"`
- `user_prompt = ""`
- `raw_event = {}`

最开始怀疑：

- 插件没有加载
- 服务没有重启
- 事件字段抽取写错了

后来我们加了两层调试日志：

- [/tmp/openclaw-risk-guard-event.jsonl](/tmp/openclaw-risk-guard-event.jsonl)
- [/tmp/risk-guard-evaluate.jsonl](/tmp/risk-guard-evaluate.jsonl)

这一步终于看清两个真相：

1. `before_tool_call` 真实事件里，很多场景只有：
   - `toolName`
   - `params`
   - `runId`
   - `toolCallId`

2. 插件发给 Python 服务的请求一度被读成了空 `{}`。

### 阶段 4：修复请求体为空的问题

这是实现过程中最实质性的 bug。

根因：

- 插件使用 Node `http.request`
- 请求体没有显式写 `Content-Length`
- Python 服务当前通过 `Content-Length` 读取 body
- 结果服务端拿到空对象 `{}`，导致审计全空

修复方式：

- 在扩展请求头里显式补上 `content-length`

修复后立刻带来了这些结果：

- `web_search` 审计正常出现
- `params.query` 正常入库
- `raw_event.trace.runId/toolCallId` 正常入库

### 阶段 5：优化审批体验

审批链开始可用后，又出现一个体验问题：

- Dashboard 弹框文案太泛
- 用户看不清“到底在确认什么”

所以我们做了两层优化：

1. 风险服务按工具类型生成更明确的 `user_message`
   - `web_search` 直接显示 query
   - `sessions_send` 显示消息摘要

2. 扩展按工具类型设置审批标题
   - `web_search` -> “外部搜索待确认”
   - `sessions_send` -> “消息发送待确认”

### 阶段 6：补充桌面通知和备份审批入口

为了不完全依赖 OpenClaw 前端：

- 风险服务命中 `confirm` 时发 macOS 通知
- `8099` 审批页支持直接点：
  - 批准一次
  - 总是允许
  - 拒绝

这样就形成了“双入口”：

- 正式审批优先 Dashboard
- 调试/备份审批走 `8099`

## 当前策略设计原则

我们不是对所有工具一刀切，而是按风险层分：

### 直接放行

- 普通只读查询
- 常规本地读取
- 未命中任何敏感词的低风险操作

### 需要确认

- `web_search`
- `exec / shell / script`
- 文件写入和删除
- MCP 写操作
- skill 敏感副作用
- 对外发送与同步
- 数据库写操作
- 部署和生产变更
- 支付和下单
- 敏感信息读取

### 直接阻断

- Prompt 注入
- 绕过审批
- 索要系统提示词
- 明显隐私/凭据泄露

## 我们踩过的关键坑

### 1. TUI 不是最可靠的审批入口

经验结论：

- Dashboard 的原生审批支持更完整
- TUI 对插件级审批支持不稳定

### 2. `before_tool_call` 不一定给完整用户输入

经验结论：

- 不能假设总能拿到 `user_prompt`
- 对 `web_search` 这类工具，应该用 `params.query` 做展示 fallback

### 3. 只看数据库不够，必须把链路打点到请求级

经验结论：

- 只看最终 `evaluations` 很难知道是插件抽取失败，还是服务端读 body 失败
- `/tmp/openclaw-risk-guard-event.jsonl` 和 `/tmp/risk-guard-evaluate.jsonl` 非常关键

### 4. OpenClaw 原生审批链可能受 pairing / gateway 状态影响

经验结论：

- 插件返回 `requireApproval` 之后，不代表 UI 一定能稳定承接
- 要保留 `8099` 审批页和桌面通知这类备份路径

## 当前系统最值得保留的设计

### 1. 规则优先，模型补充

原因：

- 规则可解释
- 关键高危模式响应稳定
- 本地运行更稳
- 模型只做边缘模糊判断

### 2. 审批和审计共用一套数据模型

原因：

- 调试容易
- 复盘容易
- 后续扩展批量审批或风控报表更自然

### 3. 原始事件摘要要入库

原因：

- OpenClaw 事件结构并不完全稳定
- 如果没有 `raw_event`，很多问题只能靠猜

## 后续演进建议

### 1. 接入本地 `PrivateMask`

建议位置：

- 所有外发类工具前

建议能力：

- 隐私评估
- 脱敏重写
- 在审批文案里展示“原文 vs 脱敏后”

### 2. 降低普通 `web_search` 的确认频率

建议：

- 普通查询直接放行
- 只有包含隐私、客户、账号、内部代号时才确认

### 3. 做“批准后重放”

当前：

- 原生 Dashboard 审批能继续执行

未来可增强：

- `8099` 自己的审批页在批准后也能触发重放

### 4. 增加更细粒度策略条件

例如：

- 按来源区分 `tool / mcp / skill`
- 按 namespace 区分系统
- 按用户、会话、agent 区分策略

## 建议的维护方式

- 调策略先看 `8099` 审计页
- 看不懂事件结构先查 `/tmp/openclaw-risk-guard-event.jsonl`
- 看服务实际收到什么先查 `/tmp/risk-guard-evaluate.jsonl`
- 调整策略优先改 [config/policy.json](/Users/fanjiang/Documents/riskops/config/policy.json)
- 改完服务端逻辑重启 `python3 main.py`
- 改完扩展逻辑重启 OpenClaw / Gateway

## 一句话总结

这套系统最核心的价值，不只是“把危险工具拦下来”，而是把 OpenClaw 的工具调用变成一条可解释、可审计、可确权、可演进的安全决策链。
