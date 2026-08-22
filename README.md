# Mir Dev Studio BOT GATEWAY

多业务系统 QQ 机器人网关，内置 Flask 管理面板与开放插件体系。

一个进程同时提供：多机器人 QQ 接入（按 `app_id` 路由到各业务系统后端）+ 可视化运维面板 + 独立子进程的插件生态。适合已有 QQ 机器人业务的团队快速接入多套系统。

## 特性

- **多机器人网关**：每个机器人独立线程 + 独立事件循环，互不阻塞，按 `app_id` 路由到对应 `backend_url`
- **内嵌管理面板**（Flask，端口 9000）：登录、机器人管理、插件管理、多管理员角色、邮箱绑定 / 找回密码 / SMTP 配置、SSRF 白名单卡片、审计与调用日志、UI 动效
- **开放插件体系**：`plugins/` → `plugin_manager.py` → `plugin_worker.py` 三层解耦，插件运行在独立子进程（stdio JSON 协议），支持热加载（code_hash 变更检测）与崩溃自愈（指数退避重启）
- **安全底座**：
  - 密码 scrypt 加盐哈希；同账号 5 次失败锁定 15 分钟；单活跃会话；会话 12h 过期
  - AppSecret / SMTP 密码 Fernet 加密存储（`enc:` 前缀）
  - Bearer Token 鉴权；响应头 `nosniff` / `X-Frame-Options: DENY` / CSP
  - 插件网络请求 SSRF 防护（拒绝环回 / 私网 / 云 metadata，支持白名单，面板可操作）
  - 插件安装 zip 路径穿越校验；面板 XSS 转义
- **自拉起重启**：面板「重启网关」使用 `subprocess.Popen` 自拉起，不依赖外部守护进程
- **首次安装向导**：未初始化时访问面板自动进入网页安装向导，浏览器内创建超管账号（也可通过 `.env` 的 `ADMIN_USERNAME/ADMIN_PASSWORD` 自动建号）

## 架构

```
            ┌─────────────────────────────────────────────┐
            │              qqbot_gateway.py                │
            │  ┌──────────┐   ┌─────────────────────────┐  │
            │  │ QQ 机器人  │   │  Flask 管理面板 :9000   │  │
            │  │ 每bot一线程│   │  登录/插件/管理员/SSRF   │  │
            │  └────┬─────┘   └──────────┬──────────────┘  │
            │       │ 本地 IPC            │                 │
            │  ┌────▼─────────────────────▼─────────────┐  │
            │  │          plugin_manager.py              │  │
            │  └────┬────────────┬────────────┬─────────┘  │
            │  plugins/ 目录：plugin_worker 子进程（隔离）  │
            └─────────────────────────────────────────────┘
```

网关主程序不 `import` 任何插件；插件宿主监听 `plugins/` 目录实现热加载。类比 MC 的 `mods/` 目录 + Forge/Fabric 加载器。

## 快速开始

### 环境要求

- Python 3.9 ~ 3.12（推荐 3.11）
- pip 依赖：`qq-botpy`、`cryptography`、`flask`

### 安装

```bash
# 解压部署包到目标目录，然后：
pip install -r requirements.txt

# 复制环境变量模板
cp .env.example .env        # Windows: copy .env.example .env
# 编辑 .env，至少填入 QQ_BOT_SECRET_KEY
```

### 启动

```bash
python qqbot_gateway.py
```

浏览器访问 `http://<IP>:9000`。首次启动（未检测到管理员）自动进入**网页安装向导**，填写账号 / 密码 / 邮箱创建超管。

### 配置机器人

在面板「机器人管理」中添加机器人，填写 `app_id` / `app_secret`（保存时自动加密存储）与业务系统 `backend_url`，网关按 `app_id` 将 QQ 消息路由到对应后端。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `QQ_BOT_SECRET_KEY` | （空） | Fernet 密钥，用于加密机器人 AppSecret 与 SMTP 密码。生成：`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `GATEWAY_PANEL_HOST` | `0.0.0.0` | 面板绑定地址；生产环境建议 `127.0.0.1` + Nginx/Caddy HTTPS 反代 |
| `GATEWAY_PANEL_PORT` | `9000` | 面板端口 |
| `GATEWAY_SESSION_TIMEOUT` | `43200` | 会话超时秒数（默认 12 小时） |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | （空） | 仅首次创建管理员时生效；留空则走网页安装向导 |
| `GATEWAY_SSRF_ALLOWED_CIDRS` | （空） | 插件 SSRF 内网白名单（逗号分隔 CIDR，默认空 = 全拦截内网/环回） |

已存在的环境变量优先级高于 `.env`。

## 插件开发

插件位于 `plugins/<plugin_id>/`，每个插件包含 `manifest.json` 与入口 Python 文件。详见「文档/网关项目文档.docx」中的插件开发指南章节，以及内置示例 `plugins/core-review/`。

插件在独立子进程中运行，通过受限 Host API（`send_text` / `http_request` / `get_bot_list` / `log` / `emit_event`）与网关通信，崩溃不影响网关主程序。

## 安全策略

发现安全漏洞请参考文档内报告，请勿公开披露。

## 更新与回滚

Windows 使用 `update.ps1` / `rollback.ps1`（白名单替换核心文件、黑名单保留配置与插件）。Linux 手动替换 4 个核心文件后重启。完整使用文档见「文档/网关项目文档.docx」（包含项目说明、贡献指南、安全说明、更新记录、插件开发指南与部署指南）。

## 许可证

[Apache License 2.0](LICENSE)

Copyright 2026 Mir Dev Studio
