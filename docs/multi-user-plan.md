# 多用户与付费接入改造方案

## 1. 现有能力速览
- **服务框架**：Node.js + Express，Redis 作为主数据源；支持多 Claude/OpenAI/Gemini 等账号路由与限流，提供 CLI 与 Web 管理端 (`web/admin-spa`).
- **用户体系**：`config.userManagement` 与 `userService` 已支持用户信息、会话与 API Key 关联，但当前仅通过 LDAP 登录，缺乏自助注册/密码登录、订阅状态字段。
- **访问控制**：API Key 层面具备并发、用量、费用限制（`apiKeyService` + Redis usage 统计），能阻断禁用用户/Key；尚未与“付费状态”打通。
- **管理界面**：Admin SPA 可查看/管理 API Keys、账号、用量，具备用户列表 API；用户门户提供 API Key 自助管理，但无付费流程入口。

## 2. 目标能力
- 支持自助注册/登录、邮箱验证及密码找回，兼容现有 LDAP 管理员登录。
- 引入套餐/订阅模型：配置套餐价格、权益（可用模型、每日/周期 token/费用上限、并发数等）。
- 接入支付（国际建议 Stripe，国内可选微信/支付宝聚合服务），自动核销，允许余额/一次性充值或订阅周期扣费。
- 用户付费后自动发放/激活 API Key，并按照套餐实时校验用量、状态（到期、欠费、冻结等）。
- 管理端/用户端新增账单、支付记录、套餐变更、余额与消耗统计视图。
- 提供审计日志与风控告警，确保数据一致性（Redis 与持久化存储对账）。

## 3. 架构与模块扩展

### 3.1 身份与访问控制
- **账户模型重构**：新增持久化数据层（建议 PostgreSQL + Prisma/TypeORM），保存用户基础信息、密码哈希、邮箱验证状态、角色、风控标记等；Redis 保持为缓存/会话层。
- **认证策略**：
  - 默认走本地账号 + JWT/Session；可配置同时启用 LDAP（管理员或企业用户），登录成功后通过 `userService.createOrUpdateUser` 同步本地档案。
  - 引入多因素认证（TOTP）作为可选项，增强付费用户安全。
- **权限模型**：`role` 字段扩展为 `admin`、`operator`、`user` 等，并增加 `accountStatus`（active/suspended/past_due）。中间件中在验证 API Key 时同步校验 `accountStatus` 与订阅状态。

### 3.2 套餐、计费与支付
- **套餐定义**：新表 `plans` 描述价格、周期（按月/按年/按次）、包含模型、费用/令牌/并发上限、是否支持超额等。
- **用户订阅**：新表 `subscriptions` 记录当前套餐、开始/结束时间、续订策略、超额计费规则、最近账单状态。
- **支付集成**：
  - 抽象 `PaymentProvider` 接口，首期实现 Stripe（国际）、Ping++/易宝/自建微信支付宝（国内）两套 provider。
  - 支持一次性购买（充值余额、购买套餐）与自动续费订阅；支付结果通过 Webhook -> `webhookService` -> 新增 `billingService` 落库，触发发票/通知。
- **账单流水**：新增 `invoices` / `payments` / `transactions` 表，记录金额、税率、通道、状态、对账信息；Redis 中保留近期缓存方便前端展示。
- **余额与授信**：允许账户余额支付，余额不足时可限制 API Key，或进入宽限期逻辑（定时任务处理）。

### 3.3 用量与权限联动
- **用量统计整合**：保留 Redis 实时统计，新增异步流水（写入 `usage_records` 表，按日汇总）用于账单生成。可借助队列（BullMQ/Redis Stream）异步落库。
- **API Key 生命周期**：
  - 购买套餐成功 -> 创建绑定用户的 API Key（调用现有 `apiKeyService.generateApiKey`，设置套餐特定限制/标签）。
  - 定时任务或中间件检测订阅状态：到期/欠费 -> 标记 Key 为 `isActive=false`、通知用户。
  - 支持用户升级/降级时重新生成或调整 Key 限制。
- **模型/速率授权**：套餐参数映射到 Key 的 `permissions`、`restrictedModels`、`concurrencyLimit`、`rateLimitCost` 等字段，实现精细化控制。

### 3.4 数据存储与迁移
- **新增数据库**：推荐 PostgreSQL（生产）/SQLite（开发），使用 Prisma/TypeORM 管理 schema、迁移、关系。
- **迁移策略**：
  1. 引入数据库连接与 ORM，编写迁移脚本创建用户、计划、账单等表。
  2. 在初始化时读取 Redis 现有用户 -> 写入新表 `users`，保留 Redis 作为缓存与兼容层。
  3. 为关键 Redis 集合（API Key、Usage）增加 nightly 对账任务，将异常写入告警。
- **配置调整**：新增数据库配置段 `config.database`，通过环境变量管理连接、迁移开关。

### 3.5 前端与管理界面
- **用户门户**：在 `web/admin-spa` 拆分/新增用户中心（或引入独立前端），提供：套餐选择、支付、账单历史、API Key 管理、个人信息、余额充值等视图。
- **管理员后台**：
  - 新增用户搜索、订阅状态修改、手动充值、退款、风控标记等页面。
  - 报表：收入统计、活跃订阅、用量 vs 收入、坏账预警。
- **组件库与 API**：扩展现有 REST API（`/api/admin`, `/api/user`）以支持套餐/支付/订阅 CRUD；必要时增加 Webhook/回调接口。

### 3.6 后台任务与通知
- **任务调度**：使用 `node-cron` 或 BullMQ 对接 Redis：
  - 每日生成账单、扣费、检查到期订阅。
  - 同步支付 Webhook 数据、处理失败重试。
  - 审计日志归档、异常告警（如 Redis 与数据库用量不一致）。
- **通知渠道**：邮件（Nodemailer）、Telegram/企业微信等；提醒支付成功、余额不足、套餐到期。

### 3.7 安全与合规
- 加强输入校验与速率限制（原有 Login RateLimiter 扩展到注册、支付接口）。
- 密码哈希使用 Argon2/bcrypt，敏感数据加密（遵循 `config.security.encryptionKey`）。
- 符合当地法规（如税率、发票、数据留存），提供导出/删除数据能力。
- 对支付 Webhook 做签名验证、防重放；对账任务比对支付平台流水与本地记录。

## 4. 实施路径（建议分阶段）

1. **准备阶段**
   - 选型数据库与 ORM，落地基础 `config.database`、迁移框架。
   - 抽象用户模型：实现邮箱密码注册、JWT 登录、邮箱验证，兼容 LDAP。
2. **套餐与订阅最小闭环**
   - 建立 `plans`、`subscriptions`、`transactions` 基础表、API、后台管理界面。
   - 以“手动标记支付成功”方式打通：管理员录入付款 -> 系统发放 API Key。
3. **支付集成与自动化**
   - 接入首个支付通道（Stripe 或国内聚合），实现支付创建、回调核销。
   - 自动生成账单/订阅续费逻辑，联动 API Key 激活/停用。
4. **用量与账单同步**
   - 完成 Redis → 数据库 usage 异步落库、对账、报表。
   - 前端展示余额、消费曲线，管理员报表上线。
5. **增强与优化**
   - 上线提醒通知、风控策略、库存管理（多账号池）、分销/邀请码。
   - 编写自动化测试（鉴权、支付回调、限流），完善文档与运维手册。

## 5. 配置与运维要点
- 新增环境变量：`DATABASE_URL`、`PAYMENT_PROVIDER`, `STRIPE_SECRET`, `ALIPAY_APP_ID` 等，集中在 `config/config.js` 管理。
- CI 延伸：在 GitHub Actions/自建流水线中加入数据库迁移、集成测试；支付接口使用 mock/stub。
- 日志与监控：扩展 `logger` 与 `webhookNotifier`，记录支付事件、异常；可接入 Prometheus/Grafana。
- 备份策略：数据库定期备份，Redis 做持久化/主从；支付签名密钥安全存储（Vault/KMS）。

## 6. 待确认的问题
- 目标用户区域与支付通道优先级？（影响 Stripe vs 国内通道选择）
- 是否需要支持企业开票、税务需求？
- 现有 LDAP 是否继续使用？若企业用户走 LDAP，需要如何与付费体系对齐？
- 是否计划支持分享/团队账号（Team Billing）或按成员拆分用量？
- 对于 API Key 使用的计费模型：按照 token、调用次数、或模型区分价格？

> 建议先在测试环境完成 Phase 1~3，验证注册->支付->Key 发放闭环，再逐步迁移现有自用配置。
