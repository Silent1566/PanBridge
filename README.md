# PanBridge

一个基于 Go 的盘搜聚合服务，包含：

- ZX 搜索入口：`/api/search`
- PG 搜索入口：`/s/`
- 配置面板：`/config`
- 黑名单 / 自动封禁 / GeoIP / 链接检测

## 本地开发

### 环境要求

- Go `1.25+`

### 安装依赖

```bash
go mod tidy
```

### 运行

```bash
go run .
```

或：

```bash
go build .
./panbridge
```

Windows：

```powershell
go build .
.\panbridge.exe
```

## 测试

```bash
go test -v ./...
```

## 关键环境变量

- `PORT`：服务端口，默认 `10199`
- `P2T_DB_PATH`：SQLite 数据库路径，默认 `p2t.db`
- `LOG_LEVEL`：`DEBUG` / `INFO` / `WARN` / `ERROR`
- `AUTO_BLOCK_IP`：是否按风险评分自动封禁命中未知路径/蜜罐路径的 IP
- `ADMIN_TOKEN`：后台登录使用的管理员 token

## 后台访问说明

### 真实后台入口

这个项目的真实后台不是首页 `/`，而是：

- 配置后台：`/config`
- 统计后台：`/stats`
- 登录入口：`/admin/login`

例如：

- `http://127.0.0.1:10199/admin/login`
- `http://127.0.0.1:10199/config`
- `http://127.0.0.1:10199/stats`

### 首页 `/` 是什么

首页 `/` 现在是一个普通落地页，用来说明：

- ZX / PG 接口入口
- 后台真实入口
- 登录方式说明

它不再承担“伪登录页”功能。

### 后台鉴权方式

后台鉴权依赖环境变量 `ADMIN_TOKEN`，但不再通过 URL `?token=` 传参。

当前方式为：

- 访问 `/admin/login`
- 提交 `ADMIN_TOKEN`
- 登录成功后由服务端签发 `HttpOnly` Session Cookie
- 后台页面和后台 API 统一依赖 Cookie 会话鉴权

这样可以避免 token 暴露在：

- 地址栏
- 浏览器历史
- 截图
- 代理或访问日志

### `ADMIN_TOKEN` 未设置时

如果没有设置 `ADMIN_TOKEN`，后台接口默认不做鉴权，可以直接访问：

- `/config`
- `/stats`

### 如何确认后台地址

程序启动日志会输出管理界面地址：

- 设置了 `ADMIN_TOKEN`：

```text
后台登录页 → http://0.0.0.0:10199/admin/login
后台页面 → 登录后访问 /config 与 /stats
```

- 未设置 `ADMIN_TOKEN`：

```text
管理界面 → http://0.0.0.0:10199/config
```

## 未知路径拦截 / 蜜罐防护

项目保留了“识别异常访问并自动拉黑”的思路，但实现方式已改为：

- 白名单路径：真实业务入口直接放行
- 未知路径：返回 `404`，并累计风险分
- 蜜罐路径：命中后大幅增加风险分
- 高频探测 / 可疑 UA / 异常方法：额外加分
- 达到阈值后自动封禁

### 典型蜜罐路径

例如：

- `/.env`
- `/.git/config`
- `/wp-login.php`
- `/wp-admin`
- `/phpmyadmin`
- `/manager/html`
- `/actuator`

### 风险评分策略

当前默认逻辑：

- 普通未知路径：`+1`
- 蜜罐路径：`+8`
- 短时间高频探测：额外 `+3`
- 可疑 User-Agent：额外 `+2`
- 异常 HTTP 方法：额外 `+1`

### 自动封禁阈值

当 `AUTO_BLOCK_IP=true` 时：

- 分数 `>= 8`：封禁 `1h`
- 分数 `>= 12`：封禁 `24h`
- 分数 `>= 20`：永久封禁

当 `AUTO_BLOCK_IP=false` 时：

- 只记录风险日志
- 不自动拉黑

### Docker 运行时设置后台 Token

如果通过 Docker 运行，建议显式设置 `ADMIN_TOKEN`：

```bash
docker run -d \
  --name panbridge \
  -p 10199:10199 \
  -e ADMIN_TOKEN=your-token \
  -v panbridge-data:/app/data \
  ghcr.io/silent1566/panbridge:latest
```

## GitHub Actions 自动打包

项目已内置 GitHub Actions：

- 每次 push / PR 自动执行 `go test`
- 自动构建：
  - `windows-amd64`
  - `linux-amd64`
  - `darwin-amd64`
  - `darwin-arm64`
- 自动上传构建产物
- 当推送标签 `v*` 时，自动创建 Release 并附带压缩包

## GitHub 自动构建 Docker 镜像

项目已内置 Docker 镜像工作流：

- 工作流文件：`.github/workflows/docker-image.yml`
- 镜像仓库：`ghcr.io/<github用户名>/<仓库名>`
- 触发条件：
  - push 到 `main`
  - push tag `v*`
  - PR 时只构建校验，不推送

### 常用镜像标签

- `ghcr.io/silent1566/panbridge:latest`（默认分支）
- `ghcr.io/silent1566/panbridge:main`
- `ghcr.io/silent1566/panbridge:sha-<commit>`
- `ghcr.io/silent1566/panbridge:v1.0.0`（tag 发布）

### 运行示例

```bash
docker run -d \
  --name panbridge \
  -p 10199:10199 \
  -v panbridge-data:/app/data \
  ghcr.io/silent1566/panbridge:latest
```

### 发布示例

```bash
git tag v1.0.0
git push origin v1.0.0
```
