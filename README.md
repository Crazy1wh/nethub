# 内网导航 (lan-nav)

自动发现局域网内所有 Web 服务的导航面板。部署后无需任何配置，自动扫描网段、抓取站点标题和图标，生成深色卡片式导航页，作为内网服务的统一入口。

## 功能

- **自动发现**：扫描子网常见 HTTP 端口 + 本机全端口(1-65535)，自动收录网页服务
- **智能过滤**：仅收录真正的网页（解析 Content-Type 与 `<title>`），API 端口、设备端口、404 空页自动忽略
- **标题/图标抓取**：自动抓取每个站点的 `<title>` 和 favicon，无需手动录入
- **两种分组视图**：默认按逻辑分组（可手动分类），一键切换按 IP 分组
- **状态实时更新**：在线/需认证/离线状态点，定时自动重扫（默认 6 小时），也可手动触发
- **手动管理**：改名、分组、隐藏、删除、手动添加，全部 AJAX 操作不刷新页面
- **搜索过滤**：按名称、地址、分组、IP 实时过滤

## 自动发现原理

1. **端口扫描**：子网 `192.168.1.0/24` 常见 Web 端口（80/443/3000/8080 等 18 个）+ 本机全端口并发扫描（600 线程，约 20 秒）
2. **HTTP 探测**：对每个开放端口并发请求（16 线程），解析响应状态、Content-Type、`<title>`、favicon
3. **网页判定**：2xx/3xx 需 `text/html` 或带 `<title>`；401/403 需 HTML 且带标题；404/5xx、JSON API、纯文本端口一律过滤
4. **入库展示**：结果存入 SQLite，卡片页展示，支持改名/分组/隐藏，下次扫描只刷新状态不覆盖用户修改

## 部署

### Docker Compose（推荐）

```bash
git clone https://github.com/Crazy1wh/lan-nav.git
cd lan-nav
docker compose up -d --build
```

访问 `http://<主机IP>/` 即导航页。数据保存在 `./data/`（SQLite + 图标缓存），可挂卷备份。

> 使用 `network_mode: host`，因为需要扫描宿主机自身的回环端口（如仅绑定 127.0.0.1 的服务）。本机默认部署在 80 端口。

### 直接运行

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 80
```

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SCAN_SUBNET` | `192.168.1.0/24` | 扫描的网段（CIDR） |
| `SCAN_PORTS` | 见代码 | 子网扫描的常见端口列表（逗号分隔） |
| `SCAN_FULL_PORTS` | `1` | 是否对本机 IP 全端口(1-65535)扫描 |
| `SCAN_INTERVAL_HOURS` | `6` | 自动重扫间隔（小时） |
| `OWN_PORT` | `80` | 本服务端口（扫描时排除自身） |
| `DATA_DIR` | `./data` | 数据目录 |

## API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/sites` | 站点列表（含本机 IP 用于分组） |
| POST | `/api/sites` | 手动添加站点 |
| PUT | `/api/sites/{id}` | 改名 / 分组 / 隐藏 |
| DELETE | `/api/sites/{id}` | 删除站点 |
| POST | `/api/scan` | 触发重新扫描 |
| GET | `/api/scan/status` | 扫描状态与最近一次日志 |

## 技术栈

FastAPI + SQLite + 原生 JavaScript（无构建、无框架），单文件后端，深色主题。

## License

MIT
