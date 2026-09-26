<div align="center">

# WG-PROXY-PANEL

**用于监控和管理 WireGuard 与 Squid 代理的单文件 Web 面板。**<br>
仅使用 Python 标准库——无需 pip 包，无需构建，支持四种语言。

[![verify](https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/actions/workflows/verify.yml/badge.svg)](https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/actions/workflows/verify.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen.svg)
![Languages](https://img.shields.io/badge/UI-EN%20%C2%B7%20FA%20%C2%B7%20RU%20%C2%B7%20ZH-orange.svg)

[English](README.md) · [فارسی](README.fa.md) · [Русский](README.ru.md) · **中文**

</div>

---

整个应用只有一个文件 `wg_panel.py`，**除 Python 标准库外不依赖任何东西**。
将它作为 systemd 服务运行（或使用随附的 Docker 容器），即可获得一个管理本机
WireGuard 接口的 Web 面板：每个客户端的实时流量、添加和停用客户端、二维码和
分享链接、限速和流量配额、专业图表、备份、操作审计日志、高级 Telegram
机器人以及 Prometheus 指标。

它最初是为一台既没有 Docker 也没有 pip 的服务器开发的，因此部署面板只需复制
一个文件。

<p align="center">
  <img src="docs/screenshots/overview.png" width="900"
       alt="WG-PROXY-PANEL 仪表盘：服务器仪表和 WireGuard 客户端列表，含实时流量、配额和限速">
</p>
<p align="center"><sub>本 README 中的所有截图均为虚构的演示数据——参见<a href="#screenshots">截图</a>。</sub></p>

## 目录

- [截图](#screenshots)
- [功能](#features)
- [图表引擎](#chart-engine)
- [语言](#languages)
- [系统要求](#requirements)
- [使用 Docker 快速开始](#quick-start-with-docker)
- [使用 systemd 安装](#install-with-systemd)
- [升级](#upgrading)
- [配置](#configuration)
- [Prometheus](#prometheus)
- [安全](#security)
- [故障排查](#troubleshooting)
- [开发](#development)
- [仓库结构](#repository-layout)
- [参与贡献](#contributing)
- [支持项目](#support)
- [许可证](#license)

<a id="screenshots"></a>

## 截图

<table>
  <tr>
    <td width="50%" valign="top">
      <a href="docs/screenshots/client-chart.png"><img src="docs/screenshots/client-chart.png" alt="单个客户端 30 天流量图，含总量、平均值、峰值、p95 和月底预测"></a>
      <p align="center"><b>客户端流量图</b><br><sub>30 天每日用量，含平均值、峰值、p95、与上一周期的对比以及月底预测</sub></p>
    </td>
    <td width="50%" valign="top">
      <a href="docs/screenshots/heatmap.png"><img src="docs/screenshots/heatmap.png" alt="按星期和小时统计的客户端用量热力图"></a>
      <p align="center"><b>星期 × 小时热力图</b><br><sub>客户端何时使用连接，以及最繁忙的时段</sub></p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <a href="docs/screenshots/rtl-fa.png"><img src="docs/screenshots/rtl-fa.png" alt="波斯语界面，从右到左布局"></a>
      <p align="center"><b>波斯语，从右到左</b><br><sub>同一面板的波斯语界面——四种界面语言之一</sub></p>
    </td>
    <td width="50%" valign="top">
      <a href="docs/screenshots/light.png"><img src="docs/screenshots/light.png" alt="浅色主题下的面板"></a>
      <p align="center"><b>浅色主题</b><br><sub>深色和浅色主题，可在工具栏中切换</sub></p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <a href="docs/screenshots/config-qr.png"><img src="docs/screenshots/config-qr.png" alt="客户端的 WireGuard 配置及二维码"></a>
      <p align="center"><b>客户端配置和二维码</b><br><sub>复制配置、下载 <code>.conf</code> 文件或扫描二维码</sub></p>
    </td>
    <td width="50%" valign="top">
      <a href="docs/screenshots/telegram-chart.png"><img src="docs/screenshots/telegram-chart.png" alt="Telegram 机器人绘制的 PNG 流量图"></a>
      <p align="center"><b>Telegram 机器人生成的图表</b><br><sub>机器人用纯 Python 自行绘制 PNG</sub></p>
    </td>
  </tr>
</table>

<p align="center">
  <a href="docs/screenshots/share-mobile.png"><img src="docs/screenshots/share-mobile.png" width="260" alt="手机上的分享页面：配置、二维码、下载按钮和用量图"></a><br>
  <b>手机上的分享页面</b><br><sub>分享链接的接收者看到的内容：配置、二维码、下载按钮以及自己的用量</sub>
</p>

> [!NOTE]
> 这些截图取自一个真实运行、但填充了**虚构数据**的面板：虚构的客户端名称、
> 生成的密钥、示例域名 `vpn.example.com`，以及 RFC 5737 文档保留网段中的 IP
> 地址。其中不包含任何真实的服务器、用户或密钥。所有截图都可以用
> `python3 demo/screenshots.py` 重新生成。

<a id="features"></a>

## 功能

### 为每个 WireGuard 客户端设置限速和流量配额

- **按客户端限速**（单位 Mbit/s），通过 `tc htb` 在 Linux 内核中执行——下载在
  WireGuard 接口本身上限速，上传通过 `ifb` 设备限速。此功能完全可选：在你限制
  任何人之前，面板完全不会触碰 `tc`，未设限的客户端不受任何影响。
- 每个客户端都可设置**月度流量配额**、**总流量上限**和**到期日期**。
- 客户端达到上限时，面板会自动处理：**停用**该客户端（默认）或将其**删除**，
  把事件写入审计日志，并发送 Telegram 告警。即将到期的账户（默认提前 3 天）
  也会收到提醒。
- Squid 代理用户同样支持：配额、限速和到期日期。

### 专业图表

- 基于 canvas 自研的图表引擎，不依赖任何图表库：真实时间轴上的折线图和柱状图、
  **缩放**、**对数刻度**、无数据处显示断点、悬停显示数值、可单独开关每条曲线，
  以及全屏视图
- 时间范围：**实时、1 小时、24 小时、7 天、30 天和 6 个月**
- 每个客户端、每个接口和每条出口隧道的流量图表
- **「星期 × 小时」热力图**，显示每个客户端在什么时候使用连接
- CPU、内存和磁盘的实时仪表；WARP 的延迟和路由图表
- 每个分享页面都有用量图表，让客户端能看到自己的用量

它如何工作、能做什么：[图表引擎](#chart-engine)。

### 高级 Telegram 机器人

机器人运行在面板进程内部，无需额外服务。它是管理服务器的第二条完整途径——
不需要 SSH，也不需要浏览器：

- **18 条命令**和按钮菜单：创建、查看、重命名、启用/停用和删除 WireGuard
  客户端及代理用户；设置**配额**和**限速**；发送**配置文件**和**二维码**
- **以图片形式发送图表**——机器人自己绘制 PNG（纯 Python，不依赖图像库）：
  客户端流量（24 小时 / 7 天 / 30 天 / 6 个月）、代理流量和测速结果，并在说明
  中附上总量、平均值和峰值
- 在线用户、搜索、按到期时间和按用量排序的报告、备份状态、测速，以及每日或
  每周摘要
- **12 类告警**：出口隧道断开/恢复、达到配额、账户即将到期、CPU/RAM/磁盘占用
  过高、swap 使用、多次登录失败、备份上传失败、网速下降、面板重启等
- 在 Telegram 中一键**批准面板登录**（可选）
- 机器人用户的角色（`owner`、`admin`、`viewer`），每个会话可使用不同语言

### 其他功能

**客户端**

- 根据最近一次握手时间判断在线/离线状态，每个客户端的实时收发流量（每 2 秒
  采样一次）
- 添加客户端（生成密钥对，从地址池中选取空闲地址）和删除客户端
- 同时在运行中的接口**和**配置文件中启用或停用客户端，使更改在重启后依然有效
- 现成的客户端配置，附带复制、下载按钮和二维码
- **分享链接**——一个独立页面，包含二维码、下载按钮和用量图表，用于把配置发给
  他人。链接有效期为 1 分钟到 24 小时，可设为一次性，也可随时撤销。页面语言
  根据接收者的浏览器自动选择。

**服务器**

- 出口隧道状态：endpoint、实时速率、systemd 单元状态
- 支持 WireGuard 和 AmneziaWG 接口
- Squid 代理用户管理
- Cloudflare WARP 状态，以及一个可选的 SNI 分流服务，按目标主机名路由连接
- 只读的泄漏审计（路由；DNS 和 IPv6 通过 Telegram 机器人）
- 备份与恢复；每个配置文件在写入前都会自动备份，且写入是原子操作
- 记录所有操作的审计日志：谁、做了什么、结果如何
- 电视/信息亭视图，轮播各状态页面，包括一个 3D 网络场景

**访问控制**

- 多用户；内置 `admin` 和 `viewer` 角色，并可基于细粒度权限目录创建自定义角色
- 可选的 TOTP 双因素认证，以及可选的通过 Telegram 批准每次面板登录
- 签名的会话 Cookie、登录频率限制、可选的 IP 白名单
- 位于 `/metrics` 的 Prometheus 指标，由 Bearer 令牌保护

<a id="chart-engine"></a>

## 图表引擎

面板里的所有图表都来自一个为本项目从零编写的小型绘图引擎：纯 Canvas 2D，
约两千行 JavaScript，就写在 `wg_panel.py` 里。不用任何图表库，也不依赖 CDN，
所以在无法上网的服务器上同样可用。引擎理解自己绘制的数据：它知道什么是配额、
客户端何时被停用，以及某条隧道在过去十秒里传输了多少字节。

### 能画什么

| 图表 | 位置 | 显示内容 |
|---|---|---|
| 流量 | 每个客户端、接口和出口隧道 | 接收与发送，外加一条虚线表示总量；“实时”和“1 小时”为折线，24 小时及以上为柱状 |
| 热力图 | 任意流量图，7 天或 30 天 | 一周中每天每个小时的平均用量，以及最繁忙的时段 |
| 按客户端分解 | 每个 WireGuard 接口 | 接口流量在各客户端之间的分配：前 7 名，其余合并为“其他” |
| 对比 | 任意选中的一组图表 | 多个客户端、隧道或接口以折线画在同一坐标轴上 |
| 用量总览 | WireGuard 客户端区域 | 某接口所有客户端随时间的堆叠用量 |
| 服务器仪表 | CPU、内存、磁盘、面板 CPU 与面板内存 | 每个仪表背后的历史 |
| 测速 | 测速区域 | 下载和上传（Mbit/s），延迟画在第二坐标轴 |
| WARP | WARP 区域 | 直连与经 WARP 的响应时间，以及流向 AI 服务的流量占比 |
| 路由质量 | 服务可达性诊断 | 每条被测路由的通话质量（MOS）和往返时间 |
| 分享页面 | 分享链接打开的页面 | 接收者本人最近 30 天的用量；若有配额，还显示每日额度 |

### 数据从哪里来

| 区间 | 每个点代表 | 保留 |
|---|---|---|
| 实时 | 一次 2 秒采样 | 最近 3 分钟，内存中 |
| 1 小时 | 10 秒平均值 | 最近 1 小时，内存中（重启后重新开始） |
| 24 小时 | 1 小时 | 约 21 天，SQLite |
| 7 天 · 30 天 · 6 个月 | 1 天 | 约 400 天，SQLite；6 个月视图可按周汇总 |

代理用户的流量根据 Squid 访问日志统计，其图表从 24 小时视图开始。热力图由
按小时的记录构成，因此最多能回看约 21 天。

### 图表上方的数字

- **接收、发送、总计**：在“实时”和“1 小时”下是当前速率；在更长的区间里是
  整个区间的总量。
- **平均**、**峰值**，以及 **p95**：区间内 95% 的小时或天数都不超过的值，
  因此单次尖峰不会左右它。
- **较上一区间**：与紧挨着的前一个等长时段相比的变化。琥珀色 ▲ 表示更多，
  绿色 ▼ 表示更少。
- **月末预测**，适用于设有月度配额的客户端：把本月至今的用量按整月推算；
  如果速度过快，会提示“约 N 天后配额用尽”。
- **记录起始于**：第一天有数据的日期，避免把较短的历史误认为用量少。

在图表本身上，一个金色圆点标出峰值；设有配额的客户端还会有一条虚线，表示
每天应得的额度。

### 如何使用图表

- **悬停**可查看该时刻所有数据系列的值。打开多个图表时，它们会同步跟随同一
  时刻。
- **缩放**：在图表上拖动以框选时间段，或使用鼠标滚轮；在手机上用双指开合。
  放大后，拖动即可沿时间轴平移。双击或点击 **↺ 完整区间** 恢复原状。纵轴会
  根据可见部分自动调整。
- **点击图例项**可隐藏或显示对应系列。
- **log** 切换为对数刻度，让用量很小和很大的客户端都能在同一张图上看清。
- **🚩** 在时间轴上标出审计日志中的变更：客户端被停用或隧道断开时为红色，
  恢复时为绿色，其他变更为蓝色。在隧道的图表上，断开的时段还会以红色阴影
  标出。把鼠标移到旗标附近，可以看到发生了什么、由谁操作以及原因。WARP
  接口的图表还会显示 WARP 自身的事件，例如切换到备用密钥。
- **⛶ 放大** 以全屏打开图表，**＋ 对比** 把它加入对比。
- **🔗** 复制指向当前视图的链接：同一张图表、同一区间、同一缩放，以及对数、
  热力图或按客户端分解模式。
- **PNG** 以屏幕原生分辨率保存图表并附上标题。**CSV** 以 UTF-8 保存原始数据，
  可直接用表格软件打开。

每个已打开图表的区间、刻度和隐藏的系列都会记在浏览器中。

### 如实呈现

- 从 1 小时视图起，时间轴是真实时间：没有数据的小时保持空白，缺数据的地方
  折线会断开，而不是直接连过去。
- 在 1 小时视图中，静默的客户端显示为真实的零线而不是空白：面板连“没有流量”
  也会记录。
- 坐标轴使用整齐的步长（1、2、2.5 或 5 × 10ⁿ），字节按 1024 进位。速率单位是
  字节每秒；测速单位是 Mbit/s。
- 图表按屏幕的实际像素密度绘制，在高分辨率屏幕上依然清晰，窗口大小变化时会
  重新绘制。
- 数据每 2 秒更新一次，但鼠标停在图表上时会暂停，图表不会在光标下跳动。

### 颜色与语言

图表的颜色取自页面主题，因此会随深色和浅色主题变化。**🎨** 按钮可切换为
色盲友好的配色（Okabe–Ito）；在这种配色下，发送线还会变成虚线，让各系列不仅
颜色不同，形状也不同。在波斯语界面中，图表使用波斯数字；测速、路由质量和
WARP 图表的日期使用伊朗太阳历。

### Telegram 中的图表

Telegram 机器人无法运行浏览器，所以面板也会在服务器端用纯 Python 绘制图表：
先填充像素缓冲区，在其中画线和柱，用内置的点阵字体写上标签，再用 `zlib`
打包成 PNG。图片尺寸为 900 × 400，柱状或折线。机器人发送的客户端图表、代理
图表以及定期报告都使用这些图片。

<a id="languages"></a>

## 语言

面板、审计日志、API 错误信息、Telegram 机器人和 Telegram 告警均提供**英语、
波斯语、俄语和中文**。翻译直接保存在 `wg_panel.py` 中（约两千个键），因此面板
仍然以单个文件部署。

| 位置 | 语言的选择方式 |
|---|---|
| 面板、登录页、分享页 | `?lang=` → `wgl` Cookie → 浏览器 `Accept-Language` → 波斯语 |
| Telegram 机器人 | 按会话单独设置——每位用户通过 `/lang` 选择 |
| Telegram 告警 | 机器人所有者的语言 |

波斯语页面从右到左显示，其他语言从左到右；样式表使用 CSS 逻辑属性，因此布局
会自动镜像。波斯语数字仅在波斯语中使用。标识符——客户端名称、密钥、endpoint、
IP 地址——在所有语言中都保持拉丁字符，以便搜索和复制。

内嵌的 Vazirmatn 字体覆盖波斯文和拉丁文；俄语和中文使用系统字体。不从任何
CDN 加载资源，因此面板在无法访问互联网的服务器上同样可用。

<a id="requirements"></a>

## 系统要求

- Ubuntu 22.04 或 24.04（x86_64 或 arm64），具有 root 权限
- 发行版自带的 Python 3.10 或更高版本——无需 pip 包，无需 virtualenv
- `wireguard-tools`

> [!NOTE]
> 本面板管理 WireGuard 接口，但不负责设计你的网络拓扑。Docker 安装会为你创建
> 一个接口。使用 systemd 安装时，面板管理服务器上已存在的接口。

<a id="quick-start-with-docker"></a>

## 使用 Docker 快速开始

面板和 WireGuard 运行在同一个容器中。首次启动会生成 `config.json`、服务器密钥
和自签名 TLS 证书；之后的启动只更新面板代码，不会改动你的数据。

```bash
git clone https://github.com/alibakhtiari-ux/WG-PROXY-PANEL.git
cd WG-PROXY-PANEL/docker
sudo bash host-setup.sh
(umask 077 && cp .env.example .env)
```

打开 `.env`，至少设置 `WG_SERVER_HOST`——客户端将要连接的公网 IP 地址或域名。
然后：

```bash
docker compose up -d --build
```

面板将在 `https://SERVER:8787` 上启动，使用自签名证书（在浏览器中接受一次警告
即可）。用户名为 `admin`。

> [!WARNING]
> **你输入的第一个密码会成为管理员密码。** 请在安装后立即登录，以免他人先访问
> 8787 端口。

对于无法访问互联网的服务器，可以在联网的机器上构建离线安装包，再拷贝过去。在
仓库根目录下执行：

```bash
cd docker/airgap && bash build-offline-bundle.sh --arch amd64
```

详情：[docker/README.md](docker/README.md) ·
[docker/airgap/README.md](docker/airgap/README.md)

<a id="install-with-systemd"></a>

## 使用 systemd 安装

从[最新发布版](https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/releases/latest)下载面板及其单元文件，并用发布的校验和进行核对
（也可以直接克隆仓库）：

```bash
base=https://github.com/alibakhtiari-ux/WG-PROXY-PANEL/releases/latest/download
curl -fLO "$base/wg_panel.py" -O "$base/wg-panel.service" -O "$base/qr.js" \
     -O "$base/three.module.min.js.gz" -O "$base/three.core.min.js.gz" -O "$base/SHA256SUMS"
sha256sum -c SHA256SUMS
```

面板**不会**自行创建配置：它从 `wg_panel.py` 所在的目录读取 `config.json`，
没有该文件就无法启动。安装文件和单元：

```bash
sudo install -D -m600 -o root -g root wg_panel.py /opt/wg-panel/wg_panel.py
sudo install -m644 -t /opt/wg-panel qr.js three.module.min.js.gz three.core.min.js.gz
sudo install -m644 wg-panel.service /etc/systemd/system/
```

然后创建 `/opt/wg-panel/config.json`（所有者为 root，权限 `600`）。最简示例——
`salt` 和 `hash` 为空时，首次登录会设置密码；没有 `tls_cert`/`tls_key` 时，
面板使用普通 HTTP：

```json
{
  "port": 8787,
  "users": [{"username": "admin", "salt": "", "hash": "", "role": "admin"}],
  "server_host": "vpn.example.com",
  "client_dns": "1.1.1.1, 8.8.8.8",
  "client_mtu": 1420
}
```

```bash
sudo systemctl enable --now wg-panel
```

用于备份、日志轮转、OOM 保护的可选单元以及 fail2ban 规则位于
[deploy/](deploy/) 目录。

<a id="upgrading"></a>

## 升级

面板只有一个文件，升级就是替换这个文件。`config.json` 中的设置和
`traffic.db` 中的数据都会保留；旧版配置会在面板启动时自动更新。

**使用 systemd：** 按上文下载新版本（包括 `sha256sum -c` 校验），然后：

```bash
sudo install -m600 -o root -g root wg_panel.py /opt/wg-panel/wg_panel.py
sudo systemctl restart wg-panel
```

要查看服务器上运行的是哪个构建，可将
`sha256sum /opt/wg-panel/wg_panel.py | cut -c1-12` 的输出与发布说明中的
build id 对比。各版本的变更见 [CHANGELOG.md](CHANGELOG.md)。

**使用 Docker：** 将新代码拉到服务器上（`git pull`），然后在 `docker/`
目录中执行：

```bash
docker compose up -d --build
```

> [!TIP]
> 升级前请先备份——使用面板中的 **备份 / 恢复** 按钮，或复制
> `/opt/wg-panel/`（Docker 为 `docker/data/`）。

<a id="configuration"></a>

## 配置

所有设置都保存在 `/opt/wg-panel/config.json` 中，其中大部分也可以在面板里修改。
主要的键：

| 键 | 用途 |
|---|---|
| `port` | 监听端口（默认 `8787`） |
| `tls_cert` · `tls_key` | TLS 证书和密钥的路径；缺省时使用普通 HTTP |
| `users` | 面板账户（PBKDF2 密码哈希）及其角色 |
| `roles` | 自定义角色及其权限 |
| `server_host` · `server_endpoint` | 写入生成的客户端配置中的地址 |
| `client_dns` · `client_mtu` · `client_allowed` | 生成客户端配置时的默认值 |
| `allow_ips` | 可选的 IP 白名单（`127.0.0.1` 始终允许） |
| `metrics_token` | `/metrics` 的 Bearer 令牌 |
| `bot` | Telegram 机器人令牌和授权用户 |
| `alerts` | Telegram 告警及其阈值 |

<a id="prometheus"></a>

## Prometheus

```yaml
scrape_configs:
  - job_name: wg-panel
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: <metrics_token from config.json>
    static_configs:
      - targets: ['your-server:8787']
```

如果使用自签名证书，请添加 `tls_config: {insecure_skip_verify: true}`，或将
证书提供给 Prometheus。

<a id="security"></a>

## 安全

- 服务以 root 身份运行，因为它需要修改网络接口和防火墙规则。其文件归 root
  所有，权限为 `600`。
- 由**面板本身**创建的客户端私钥保存在 `/opt/wg-panel/clients/`（仅 root
  可读），以便之后再次显示配置和二维码。
- **分享链接包含客户端的私钥。** 链接有效期很短，可设为一次性并可撤销，页面
  响应带有 `Referrer-Policy: no-referrer` 和 `X-Robots-Tag: noindex`——但仍请
  把每个链接当作机密对待。
- 登录限制为每个 IP 每分钟 5 次尝试，连续失败可触发 Telegram 告警。fail2ban
  过滤器和规则位于 `deploy/`。
- Telegram 机器人是完整的管理途径：授权用户列表中的任何人都可以在不使用 SSH、
  不登录面板的情况下修改服务器。
- 请用 `allow_ips` 或防火墙保护面板。使用 Docker 时请注意，`ufw` 不会过滤
  Docker 发布的端口——参见 [docker/README.md](docker/README.md)。

报告安全漏洞请参阅 [SECURITY.md](SECURITY.md)。

<a id="troubleshooting"></a>

## 故障排查

<details>
<summary><b>忘记了管理员密码，或丢失了双因素认证设备</b></summary>

<br>

停止面板并打开 `config.json`（`/opt/wg-panel/config.json`；Docker 为
`docker/data/panel/config.json`）。在 `users` 中找到该账户，将其 `salt` 和
`hash` 设为空字符串；如需同时关闭该账户的双因素认证，再将 `totp` 设为
`""`。重新启动面板：之后在登录页为该账户输入的第一个密码将成为新密码，
因此请在他人无法访问面板时进行此操作。

</details>

<details>
<summary><b>服务无法启动</b></summary>

<br>

使用 `journalctl -u wg-panel -n 50` 查看日志。最常见的原因是 `config.json`
缺失或无效：面板从不自行创建该文件（参见[使用 systemd 安装](#install-with-systemd)），
且它必须是合法的 JSON。

</details>

<details>
<summary><b>分享链接提示无效或已过期</b></summary>

<br>

分享链接在过期后、一次性链接在首次使用后，或被撤销后都会失效。页面有意
不说明具体是哪种情况。请在该客户端所在行重新创建链接。

</details>

<details>
<summary><b>修改代码后页面一片空白</b></summary>

<br>

这几乎总是 Python 字符串中的 JavaScript 出错——参见[开发](#development)
一节中的说明，并检查浏览器控制台。

</details>

<a id="development"></a>

## 开发

`wg_panel.py` 超过 30,000 行，整个 Web 界面（HTML、CSS 和 JavaScript）都以
Python 字符串的形式包含在其中。运行测试：

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile wg_panel.py
python3 tests/check_js.py      # JavaScript 语法检查，需要 Node.js
```

测试会检查的内容包括：每个翻译键在四种语言中都存在且占位符一致；翻译后的文本
绝不会成为数据（指标标签、已保存的审计记录、比较键）；没有任何私密内容进入
Docker 构建上下文；测试数据使用 RFC 5737 文档地址。本仓库中有部分测试会被跳过
（skip），因为它们检查的是未在此发布的部署工具。

> [!IMPORTANT]
> Python 看不到 JavaScript 字符串内部的错误——即使 JavaScript 有错，
> `py_compile` 依然通过，结果是浏览器中出现空白页。`tests/check_js.py`（CI 也会
> 运行）可以发现语法错误；但修改界面后，仍请打开面板并检查浏览器控制台。

**演示模式。** `python3 demo/run.py` 会在 `http://127.0.0.1:8787` 启动面板
（用户 `admin`，密码 `demo`），使用虚构的客户端、六个月的流量历史和模拟的
系统工具。它不需要 WireGuard，也不需要 root，并且不会在临时目录之外写入任何
内容。`python3 demo/screenshots.py` 会重新生成 `docs/screenshots/` 中的所有
图片；它需要 Node.js 和 Playwright，若已安装 Pillow 还会压缩图片。

<a id="repository-layout"></a>

## 仓库结构

| 路径 | 内容 |
|---|---|
| `wg_panel.py` | 整个应用 |
| `wg-panel.service` | systemd 单元 |
| `docker/` | Docker Compose 安装及离线安装包构建工具 |
| `deploy/` | 可选的 systemd 单元、fail2ban 规则、备份脚本、SNI 分流器 |
| `tests/` | 测试套件 |
| `docs/screenshots/` | README 中使用的截图 |
| `demo/` | 演示模式与截图生成器 |
| `CHANGELOG.md` | 各版本的变更 |
| `fonts/` | Vazirmatn 字体子集 |
| `qr.js` · `three.*.min.js.gz` | 随附的二维码库和 three.js |

<a id="contributing"></a>

## 参与贡献

欢迎提交问题报告和 pull request——请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。
请遵守项目的两条规则：**仅使用标准库**和**单个文件**。

<a id="support"></a>

## 支持项目

如果这个面板对你有帮助，欢迎通过捐赠支持它的持续开发：

**USDT** — USDT · TRON (TRC20)

```text
TV4R2i7yQxzEVSzZEXwBJqfhDavifaGwMt
```

**USDT 或 USDC** — USDT / USDC · BNB Smart Chain (BEP20)

```text
0x5631398273a7283d543A62336eD090101FF3D449
```

**BTC** — Bitcoin (BTC)

```text
bc1qjnmmqs5c57shld3ka90vcle4scxhszevehj4y3
```

> [!WARNING]
> 每种币**只能通过其旁边标注的网络发送**。通过其他网络发送的资金无法找回。

<a id="license"></a>

## 许可证

[MIT](LICENSE) © 2026 Ali Bakhtiari

随附的第三方组件保留各自的许可证：

- [three.js](https://threejs.org) — MIT（[three.LICENSE.txt](three.LICENSE.txt)）
- [Vazirmatn](https://github.com/rastikerdar/vazirmatn) — SIL Open Font License 1.1
