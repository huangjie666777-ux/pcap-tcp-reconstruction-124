# TCP 会话还原后端

基于 FastAPI 0.115 + dpkt 1.9 的抓包分析服务：上传经典 PCAP，自动完成
TCP 连接分代、乱序/重传/冲突重组，并按 HTTP 区间下载还原后的字节流，
供运维定位丢包（缺口）与重传冲突。

## 能力与规则

- **PCAP 读取**：经典 libpcap 格式，支持大/小端魔数与微秒/纳秒时间戳；
  仅处理 Ethernet（含 802.1Q 标签）内**未分片 IPv4/TCP**。
  IPv6、非 IP、非 TCP、IPv4 分片、非 Ethernet 链路层均按类别跳过并计数。
  容器头/记录头截断、`snaplen` 切包、IP/TCP 首部截断均报错（422），**不发布部分结果**。
- **连接分代**：双向四元组归并连接；以不带 ACK 的 SYN 开启一代。
  活动代内同序号 SYN 视为重传；新序号 SYN 或连接关闭后的 SYN 开启新一代。
  缺少起始 SYN 的报文计入 `orphan_packets`，不混入任何连接。
  双向 FIN 关闭（`close_reason=fin`）；RST 关闭（`rst`）；
  被新 SYN 取代标记 `superseded`；抓包结束仍未关闭为 `open`。
- **字节重组**：每方向以自身 SYN 后首字节为偏移 0，SYN/FIN 占序号但不输出，
  支持 32 位序号回绕。乱序按序号归位，部分重叠补齐缺口，完全相同的重传去重；
  **冲突字节保留文件中先到内容**，记录冲突区间与相关包号（不按时间戳重排）。
- **缺口**：范围到 FIN 位置或最大载荷末端，缺字节不补零；区间下载跨缺口返回 **409**。
- **限制**：上传 50 MiB、每份最多 200 代、每方向数据跨度 8 MiB，超限整份拒绝。
- **持久化**：结果写入 `data/captures/<id>/`，先写临时目录、原子重命名发布后
  才登记索引（`data/index.json`）；上传并发互不覆盖；失败清理临时数据；重启可读。

## 运行

```bash
.venv/bin/python scripts/make_sample_pcaps.py          # 生成样例到 samples/
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

存储目录可用环境变量 `PCAP_DB_DIR` 覆盖（默认 `./data`）。

## HTTP 接口

### 1. 上传 PCAP

`POST /captures`，`multipart/form-data` 字段 `file`。

```bash
curl -s -F "file=@samples/demo.pcap" http://127.0.0.1:8000/captures
```

返回：`capture_id`、各类计数（`total_packets`/`tcp_packets`/`orphan_packets`/
`skipped`）、`generation_count`。413 表示超过 50 MiB；422 表示 PCAP 损坏或超限。

### 2. 列表 / 抓包详情

```bash
curl -s http://127.0.0.1:8000/captures
curl -s http://127.0.0.1:8000/captures/<capture_id> | python -m json.tool
```

### 3. 连接代号详情（端点、关闭原因、区间/缺口/冲突/来源包号）

```bash
curl -s http://127.0.0.1:8000/captures/<capture_id>/generations/0 | python -m json.tool
```

每方向字段：

| 字段 | 含义 |
| --- | --- |
| `span` | 已知跨度末端（FIN 位置或最大载荷末端，exclusive） |
| `known_intervals` | 已有字节区间 `[start,end)` 列表 |
| `gaps` | 缺口区间 `[start,end)` 列表 |
| `conflicts` | 冲突 `{start,end,packets}`，`packets` 为相关包号 |
| `packet_numbers` | 贡献该方向数据的来源包号 |
| `retransmissions` | 完全相同的重传次数（已去重） |

### 4. 按偏移/长度下载字节

`GET /captures/<capture_id>/generations/<n>/bytes?direction=c2s|s2c&offset=O&length=L`

- 200：返回 `application/octet-stream` 原始字节；
- 409：区间跨越缺口，响应体给出缺口位置；
- 416：起始偏移超出跨度；404：抓包/代号/方向不存在。

```bash
curl -s "http://127.0.0.1:8000/captures/<id>/generations/0/bytes?direction=c2s&offset=10&length=8"
```

## 测试

```bash
.venv/bin/python -m py_compile app/*.py scripts/*.py tests/*.py
.venv/bin/python -m pytest -q
```

测试覆盖大小端/微纳秒解析、截断报错、分代（重传 SYN/新 SYN/RST/FIN/孤儿）、
32 位回绕、乱序/部分重叠/冲突保留先到内容、跨度限制、HTTP 409/416/422
以及重启后持久化读取。
