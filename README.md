# Clash Pilot

一个本地优先的 **Clash / Mihomo 网络控制台**。界面完全实现在单文件 `main.html` 中，后端使用 Python，真实代理能力由 Mihomo（Clash.Meta）内核提供。

没有安装内核时，应用会进入**内置演示模式**：所有页面、节点切换、规则编辑、连接列表和流量图表都可以体验，但不会接管系统网络，也不会产生真实代理流量。

![Clash Pilot 概览](docs/preview.png)

## 功能

- **概览仪表盘**：连接状态、实时上下行、今日流量、活跃连接、平滑流量曲线、快捷节点、最近日志。
- **代理节点**：多策略组切换、节点延迟测试（单个 / 整组）、收藏、搜索、运行模式（规则 / 全局 / 直连）。
- **订阅配置**：粘贴本地 YAML、拖拽文件、订阅链接导入、启用、刷新、导出 YAML、删除。
- **路由规则**：搜索、分页、新增、编辑、删除，支持 `DOMAIN-SUFFIX`、`IP-CIDR`、`PROCESS-NAME`、`MATCH` 等常见类型。
- **活动连接**：默认把相同品牌/图标的连接合并为一行（例如所有哔哩哔哩域名、同一主域名的子域、所有 DNS 查询分别归组），支持展开/全部展开；Visual Studio 的 `devenv.exe`、`BackgroundDownload.exe`、`ServiceHub`、`MSBuild` 等进程会合并成一个 Visual Studio 组合。自动为 Bilibili、Google、GitHub、Microsoft 等常见站点显示图标，对 IP 连接标注 DNS、内网、公网等备注。在 Windows 上还会从进程对应的 `.exe` 中提取真实程序图标。连接断开后不会消失，而是保留并标记为“已断开”；历史写入 `data/connection-history.json`，重启控制台后仍会显示之前的记录。页面会统计每个组合的累计上传/下载和总使用时长。
- **连接操作**：每条连接或整个组合都可以修改流量走向（国外流量 / 直连 / 其他策略组），无需去规则页；组合可以整体禁止联网，已全部断开的组合可以整体删除。单个连接和组合都支持禁止、关闭/删除记录。禁止规则在“禁止规则”弹窗中管理。
- **运行日志**：按级别筛选、搜索、暂停、复制、清空，实时滚动。
- **真实内核接入**：自动检测 / 手动指定 Mihomo，生成运行配置，启动和停止进程，同步策略组选择，热重载配置，延迟测试。
- **系统代理**：Windows 一键接管与恢复，修改前备份原有设置；关闭内核或应用退出时自动恢复，避免断网。
- **设置自动保存**：修改设置后立即写入并生效，无需再点击保存；端口、密钥等需要重启内核的项目会明确提示。
- **外观**：9 种主题（暗色、黑墨青蓝、赛博荧光、极光紫；亮色、樱桃粉、奶油黄、薄荷绿；跟随系统），四档全局文字大小（100% / 108% / 116% / 124%），适配桌面与移动端。
- **控制台窗口**：在设置页可以显示或隐藏启动服务的 CMD 窗口；后台/无窗口方式启动时会显示不可用提示。

<img src="docs/preview-settings-light.png" alt="浅色设置界面" width="720">

代理节点与移动端：

<img src="docs/preview-proxies.png" alt="代理节点" width="720">
<img src="docs/preview-mobile.png" alt="移动端" width="250">

## 快速开始

环境要求：Windows / macOS / Linux，Python 3.10+。

```powershell
cd "D:\My\Create\Clash-Manager"
python -m pip install -r requirements.txt
python app.py
```

也可以直接双击 `start.bat`（会检查 Python 与 PyYAML）。浏览器会自动打开，默认地址：

```text
http://127.0.0.1:8787
```

如果 8787 已被占用，控制台会自动使用后续可用端口，并在终端打印实际地址。

```powershell
python app.py --port 8899          # 指定控制台端口
python app.py --no-browser         # 不自动打开浏览器
```

## 接入真实代理

如果上次关闭控制台后 Mihomo 进程仍在后台占用 7890/9090 端口，下次启动会自动识别并结束残留的 `mihomo.exe` 进程，再启动新内核，无需手动杀进程。

演示内核不会建立任何真实代理连接。要启用真实代理：

1. 从 [Mihomo Releases](https://github.com/MetaCubeX/mihomo/releases) 下载与系统匹配的 `mihomo`（Windows 为 `mihomo.exe`）。
2. 把内核放到项目下的 `bin/mihomo.exe`，或在 **偏好设置 → 内核可执行文件** 中填写完整路径。

### Windows 版本怎么选

Mihomo 的发布页会同时列出很多构建，按下面规则选择即可：

| 系统 | 推荐资源 |
|---|---|
| Windows 10/11 64 位（绝大多数电脑） | `mihomo-windows-amd64-vX.Y.Z.zip` |
| 很老的 64 位 CPU / 启动报非法指令 | `mihomo-windows-amd64-compatible-vX.Y.Z.zip` |
| Windows ARM64 | `mihomo-windows-arm64-vX.Y.Z.zip` |
| 32 位 Windows | `mihomo-windows-386-vX.Y.Z.zip` |

带 `go120`、`go125` 等后缀的是面向特定 Go 运行时的构建，普通用户不需要；`v1`、`v2`、`v3` 是 CPU 指令集等级，现代 CPU 用无后缀版本即可。下载 zip 后，把里面的 `mihomo-windows-amd64.exe` 重命名为 `mihomo.exe` 放进 `bin/` 即可。
3. 打开 **偏好设置 → 代理内核**，选择 **Mihomo**，保存设置。
4. 进入 **订阅配置**，导入 Clash / Mihomo YAML 或订阅链接，并启用它。
5. 回到概览点击 **启动内核**。内核启动成功后，才可以在设置中打开 **系统代理**。

> 自动检测会查找 `bin/`、系统 PATH 以及一些常见安装目录。控制台不会自动下载内核。

### 演示模式与真实模式

| | 演示模式 | 真实 Mihomo |
|---|---|---|
| 节点切换 / 测速 | 模拟数据 | 调用真实内核 API |
| 流量与连接 | 模拟生成 | 来自 `/connections` |
| 系统代理 | 禁止开启 | 可开启并自动恢复 |
| 规则修改 | 写入当前 YAML | 写入 YAML 并尝试热重载 |
| 网络影响 | 不接管系统网络 | 由内核监听本地混合端口 |

## 配置导入

支持：

- 本地 Clash / Mihomo YAML（拖拽、选择文件或直接粘贴）
- `http://` / `https://` 订阅链接
- 返回纯 YAML 或 Base64 编码 YAML 的订阅

暂不支持将 Base64 的分享链接（`ss://`、`vmess://` 等）自动转换为 Clash 节点。此类链接请先在机场后台生成 Clash 订阅。

订阅内容保存在本机 `data/profiles/`，不会自动定时刷新；可在「订阅配置」中手动刷新。

## 数据与安全

- 控制台默认只监听 `127.0.0.1`，不对局域网开放，并校验 Host 与 Origin，拒绝跨站请求与 DNS rebinding。
- 所有配置、订阅、统计保存在本机 `data/`：

```text
data/
├─ state.json              # 设置、配置元数据、策略组选择
├─ stats.json              # 今日流量统计
├─ profiles/               # 各配置的 YAML 文件
├─ icons/                  # 从程序 exe 提取并缓存的图标
├─ runtime/config.yaml     # 启动真实内核时生成的运行配置
├─ runtime/core.log        # 内核日志
└─ system-proxy-backup.json# 系统代理原始设置备份
```

- 没有账号系统，没有遥测，不会上传数据。
- 系统代理修改仅写入当前用户的 Windows 注册表项，不需要管理员权限。
- 启用系统代理前会备份原设置；关闭内核、关闭应用或意外退出时，会尝试恢复原设置。
- 内核的 TUN 模式默认被强制关闭，避免控制台在无提示的情况下请求管理员权限。

## HTTP API

后端是一个轻量本地 API 服务，界面轮询以下端点：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/state` | 设置、配置列表、内核与系统代理状态 |
| GET | `/api/metrics` | 实时速率、今日流量、历史曲线 |
| GET | `/api/proxies` | 策略组、节点与延迟 |
| POST | `/api/proxies/select` | 切换策略组节点 |
| POST | `/api/proxies/test` | 单节点延迟测试 |
| POST | `/api/proxies/test-group` | 整组延迟测试 |
| GET | `/api/rules` | 当前配置的路由规则 |
| POST / PUT / DELETE | `/api/rules[/index]` | 新增 / 修改 / 删除规则 |
| GET / DELETE | `/api/connections[/id]` | 查看连接历史 / 关闭连接 |
| POST | `/api/connections/clear-closed` | 清理已断开的历史记录 |
| POST | `/api/connections/delete-history` | 按连接 ID 删除断开记录 |
| POST / DELETE | `/api/block[/id]` | 添加 / 解除域名、域名后缀或 IP 禁止规则 |
| POST | `/api/route-overrides` | 为连接或组合设置流量走向 |
| GET / POST | `/api/console/window` | 查询 / 显示或隐藏 CMD 控制台窗口 |
| GET | `/api/logs` | 增量获取运行日志 |
| POST | `/api/profiles/import` | 导入本地 YAML 或订阅 |
| POST | `/api/profiles/{id}/activate` | 启用配置 |
| POST | `/api/profiles/{id}/refresh` | 刷新远程订阅 |
| GET | `/api/profiles/{id}/export` | 导出 YAML |
| PUT | `/api/settings` | 保存设置 |
| POST | `/api/engine/start` / `stop` / `restart` | 控制内核 |
| POST | `/api/engine/system-proxy` | 开关 Windows 系统代理 |

## 项目结构

```text
Clash-Manager/
├─ main.html          # 单文件界面（HTML + CSS + JavaScript）
├─ app.py             # Python 后端、内核管理、本地 API
├─ start.bat          # Windows 启动脚本
├─ requirements.txt
├─ bin/               # 可选：放置 mihomo 内核
├─ docs/              # 预览图
└─ data/              # 首次运行自动生成
```

`main.html` 不依赖任何 CDN、前端框架或构建步骤，全部样式与交互均为内联。

`data/connection-history.json` 保存本次及历史连接记录；`data/state.json` 保存主题、文字大小、禁止规则和路由覆盖；二者的写入均为本机文件，不会上传。

## 已知限制

- 仅 Windows 支持自动配置系统代理和从 `.exe` 提取程序图标；其他系统使用品牌图标或首字母占位。
- 从程序文件提取图标需要控制台能读取对应的安装目录；失败时会自动回退为品牌图标或首字母。
- 不管理 TUN 模式、服务模式或开机自启的系统服务。
- 编辑规则会使用 PyYAML 重写当前配置文件，原有 YAML 注释不会保留。
- 演示模式的连接与流量均为模拟数据，不能作为真实网络指标。
- 断开连接历史会持久化到 `data/connection-history.json`，最多保留 2000 条已断开记录；也可以点击“清理断开”或删除某个组合来手动移除。
- 需要真实代理时，必须另外安装并配置 Mihomo；本仓库不内置内核二进制。

## 常见问题

**内核启动失败？**  
检查内核路径是否正确，控制器端口是否被其他 Clash 程序占用。详细错误会写入 `data/runtime/core.log`，界面日志也会显示摘要。

**不开启系统代理，为什么规则模式不生效？**  
Clash / Mihomo 本质上是本地代理服务，只处理主动发到 `127.0.0.1:7890` 的流量。未开启系统代理、也未配置 TUN 时，浏览器会直接联网，规则模式根本看不到这些请求。可以选择开启系统代理，或手动把浏览器/应用的 HTTP 与 HTTPS 代理设置为 `127.0.0.1:7890`。当前版本不管理 TUN。

**系统代理开关是灰色的？**  
演示模式或真实内核未运行时禁止开启系统代理，避免把系统流量指向一个不存在的本地端口。

**打开系统代理时提示“WinError 5 / 拒绝访问”？**  
控制台需要写入当前用户的 Windows 代理设置。请确认你使用的是当前登录用户，而不是受限服务账户或文件沙箱环境；正常双击 `start.bat` 启动即可。部分安全软件也会阻止修改 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`，需要放行 Python 或改用其他系统代理工具。

**订阅导入失败？**  
确认链接直接返回 Clash / Mihomo YAML，而不是网页登录页或分享链接集合。部分机场需要特定 UA，当前使用 `clash.meta` UA。

**关闭终端后网络异常？**  
正常情况下应用会恢复系统代理。若进程被强制结束，请在「设置 → 系统网络接管」中关闭系统代理，或手动关闭 Windows 的代理服务器设置。

## 开发说明

- Python 后端只使用标准库 + PyYAML，没有 Web 框架依赖。
- 界面通过 `fetch` 调用本地 API，所有状态均来自后端。
- 实时指标由后端采样线程每秒生成；演示模式与真实内核共用同一套指标模型。
- 需要修改时，前端编辑 `main.html`，后端编辑 `app.py`，重启 `python app.py` 即可。

## License

MIT
