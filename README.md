# pcapdiff · 双端 TCP 抓包字节到达证据比对

备份专线割接后，从链路两端各录制同一条 IPv4 TCP 连接的 Ethernet PCAP，查清
**发端见过的哪些字节缺少到达收端的证据**。Flask 实现，Docker Compose 一键启动，
内置样例可直接试跑。

## 它把字节分成哪三类

以起始 SYN 对齐：SYN 消耗一个序号，因此首个数据字节（序号 `ISN+1`）的偏移为 `0`。
对发端抓包中出现过的所有发起方载荷区间取并集，逐字节判定（直接抓包证据优先）：

| 分类 | 含义 |
| --- | --- |
| **收端抓到数据包** (`captured`) | 该偏移区间出现在收端抓包的 发起方→接收方 TCP 载荷并集中 |
| **仅被收端累计 ACK 确认** (`acked_only`) | 收端没抓到对应数据包，但 收端→发起方 的累计 ACK 已覆盖（取两份文件中最大 ACK 边界） |
| **收端无证据** (`missing`) | 既无收端数据包，也未被累计 ACK 覆盖 |

连续同类字节合并为一个区间；跨发端并集空洞不会被错误合并。页面同时显示十进制
和十六进制偏移（首尾采用含尾写法，另在数据属性中给出半开区间 `[start,end)`），
支持按分类筛选与分页。

## 校验规则（两份都通过后才出结果）

- 可解析的经典 PCAP（微秒/纳秒魔数、大小端）或 PCAPNG（SHB/IDB/EPB/SPB）；
- 链路层以 Ethernet（`DLT_EN10MB=1`）为准，支持 802.1Q/QinQ VLAN；同时兼容
  裸 IPv4（101/228）、Linux SLL/SLL2 与 BSD NULL 封装；
- 两份文件都必须含发起方**起始 SYN**（`SYN=1, ACK=0`），重传 SYN 自动去重；
- 两份文件的 SYN 四元组必须能对上且 ISN 一致，否则分别列出各自 SYN 并说明；
- 不允许任何 IPv4 分片（`MF=1` 或片偏移非 0），发现即报帧数与首例帧号；
- 发起方数据跨度严格小于 2 GiB（`2^31` 字节），对恰好到达序号回绕歧义边界的
  序号也能识别并判失败；
- 解析失败（魔数不对、截断、非 Ethernet 等）逐文件给出中文原因。

序号按 32 位有符号模差相对 `ISN+1` 展开，天然支持回绕；重传由区间并集去重，
两端分段不同按区间重合判定，不依赖分段边界一致。

## 快速开始

### Docker Compose（推荐）

```bash
docker compose up --build
# 打开 http://localhost:5000 （同样映射了 http://localhost:8000）
```

两个宿主机端口都指向容器内的 5000（Flask 默认 5000 与常见的 8000 约定）。
若 5000 被占用，可用 `WEB_PORT=8080 docker compose up --build` 改主端口。

上传文件与运行态 SQLite 存放在 compose 卷 `pcapdiff-data` 中。

### 本地直接运行

```bash
pip install -r requirements.txt
python app.py                 # 或 python wsgi.py，默认 0.0.0.0:5000
# 生产形态：gunicorn --bind 0.0.0.0:5000 wsgi:app
```

环境变量：`PORT`（本地入口）、`WEB_PORT`（compose 宿主机映射）、
`PCAPDIFF_VAR_DIR`（运行目录，默认仓库下 `var/`，不可写时退到 `/tmp/pcapdiff-var`）、
`PCAPDIFF_MAX_UPLOAD`（默认 8 GiB）。

## 内置样例

首页点击「使用内置样例一键试跑」，或直接访问：

- <http://localhost:5000/sample/basic> — 1000 字节，三类齐全，含重传与不同分段；
- <http://localhost:5000/sample/wrap> — ISN 接近 `2^32`，数据流跨越序号回绕。

也可用 `python tools/make_samples.py` 在 `samples/` 下生成样例 PCAP 供手工上传。

basic 样例的预期结果：

```
[0,250)   captured      [250,300)  acked_only
[300,450) captured      [450,700)  acked_only
[700,800) captured      [800,1000) missing
```

## HTTP / JSON 接口

| 方法与路径 | 说明 |
| --- | --- |
| `GET /` | 上传页 |
| `POST /`、`/analyze`、`/upload`、`/compare` | multipart 上传两份 PCAP，默认返回 HTML；`Accept: application/json` 或 `?format=json` 返回 JSON |
| `POST /api/analyze` | 纯 JSON 分析接口 |
| `GET /r/<run_id>`（别名 `/result/<id>`、`/results/<id>`） | 结果分页页 |
| `GET /api/r/<run_id>` | 结果 JSON，参数 `page`/`p`、`size`/`page_size`/`per_page`/`limit`、`cat`/`category`（`captured`/`acked_only`/`missing`，也接受中文） |
| `GET /sample/<basic\|wrap>` | 内置样例；加 `?format=json` 返回 JSON |
| `GET /healthz` | 健康检查 |

文件字段名兼容 `sender`/`receiver`、`file1`/`file2`、任意两个按顺序的文件部分、
同名 `file` 多文件等常见写法。

## 内存为什么不随包数增长

- PCAP/PCAPNG 逐帧流式读取，任意时刻内存里只有当前帧；不上 `scapy.rdpcap`
  这类整包载入。
- 每个 TCP 包只提取 `(start,end)` 区间并写入磁盘 SQLite
  （`WITHOUT ROWID` 主键自动去重完全重复的重传区间），Python 不保存包列表。
- 区间并集与三分类都走**有序游标 + 双指针**，Python 侧只有当前合并区间和
  1000 行的批量写缓冲；SQLite cache 限制约 2 MiB。
- 结果段同样落盘，分页用 `LIMIT/OFFSET` 查询。

实测（本机 Python 3.11，`python tools/selftest_memory.py`，构造大量互相分离的
1 字节区间这种最不利于区间合并的 PCAP；RSS 为独立分析子进程峰值）：

```
N=     5,000  packets  peak RSS=28.8 MiB  pcap=0.4 MB
N=    50,000  packets  peak RSS=28.8 MiB  pcap=3.6 MB
N=   200,000  packets  peak RSS=28.8 MiB  pcap=14.2 MB
N= 1,000,000  packets  peak RSS=28.6 MiB  pcap=71.0 MB
```

100 万包（含生成文件与分析）约 25 秒；峰值内存基本恒定。

## 目录结构

```
app.py                 # 仓库根 WSGI 入口（flask --app app / gunicorn app:app）
wsgi.py                # 同上，wsgi:app
pcapdiff/
  pcap_reader.py       # 流式 PCAP/PCAPNG 读取
  packet_codec.py      # Ethernet/VLAN/IPv4/TCP 解码 + 序号模差
  scanner.py           # 第一遍校验/SYN，第二遍区间与 ACK 提取
  engine.py            # SQLite 区间并集、三分类、分页查询、编排
  app.py               # Flask 路由
  sample_data.py       # 两个内置样例
  pcap_writer.py       # 零依赖 PCAP/PCAPNG 构造（样例与测试用）
  templates/ static/
tests/                 # 40 个 pytest 用例
tools/                 # 样例生成、内存自测脚本
Dockerfile docker-compose.yml requirements.txt
```

## 自测

```bash
python3 -m pip install -r requirements.txt pytest
python3 -m pytest tests/          # 40 passed
python3 tools/selftest_memory.py  # 内存恒定性
```

覆盖：三类判定、相邻同类合并、重传、乱序/异分段、序号回绕、大小端 PCAP、
PCAPNG（自带 writer 与 Scapy 生成文件互通）、TCP 选项/VLAN、缺 SYN、IP 分片
（MF 与片偏移）、四元组/ISN 不一致、垃圾文件/截断头、非 Ethernet、2 GiB
边界三种序号构造、分页/分类筛选/JSON API/字段名兼容等。

## 限制与未完成项

- 只处理 IPv4；非 IPv4（ARP/IPv6 等）帧跳过，不影响目标连接分析。
- 不做 TCP 流重组与载荷内容比对，只比较序号空间覆盖——对“哪些字节有证据”
  这一问题足够，且天然支持分段不同。
- 依赖 IP 总长/TCP 头长计算载荷；snaplen 截断时只按实际捕获字节计区间并在
  “解析明细”里报告截断包数，不做静默猜测。
- 未做用户鉴权与多连接选择 UI：按两份文件的共同起始 SYN 自动认定连接；
  若共同 SYN 不唯一会报歧义（列出四元组）。
- 运行历史不做自动清理（每次分析一个 UUID 目录），长期运行需清理卷或加定时任务。
- 本环境没有 Docker 守护进程，`docker compose up --build` 未能在交付环境实跑；
  Dockerfile/compose 已按标准 python:3.12-slim + gunicorn 编写，应用本身已用
  本机 Gunicorn 实测通过。
