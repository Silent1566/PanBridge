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
- `AUTO_BLOCK_IP`：是否自动封禁访问非白名单路径的 IP
- `ADMIN_TOKEN`：配置后台鉴权 token

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
