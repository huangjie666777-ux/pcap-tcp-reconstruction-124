# TCP 会话还原后端（FastAPI + dpkt）

上传经典 libpcap（`.pcap`）抓包文件，按四元组双向归并连接、分代重组 TCP 字节流，
用于运维定位丢包（缺口）、重传与冲突。纯 Python 3.10，FastAPI 0.115 + dpkt 1.9.8。

## 运行

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.lock
SAMPLE_PCAP=sample_capture.pcap .venv/bin/python scripts/generate_sample.py
PCAP_STORE_DIR=data/captures .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

交互文档：`http://127.0.0.1:8000/docs`。`PCAP_STORE_DIR` 默认为 `data/captures`。

## 接口

### `POST /captures`

`multipart/form-data` 上传字段 `file`。成功返回 `{"capture_id": ..., "size": ...}`。

- `200`：解析、分代、重组、持久化全部成功后才生成并可见
- `400`：非经典 PCAP、魔数/版本/链路层不支持、容器或报文截断、分片等格式错误
  （截断一律整份拒绝，不发布部分结果），或超过分代/跨度限制
- `413`：上传超过 50 MiB

### `GET /captures`

列出所有已成功导入的 `capture_id`（重启后仍可列出）。

### `GET /captures/{capture_id}`

返回整份分析结果：

```json
{
  "capture_id": "...",
  "packet_count": 19,
  "skipped": {
    "non_ipv4_ethertype": 1,
    "fragmented_ipv4": 1,
    "non_tcp": 1,
    "vlan": 0
  },
  "missing_syn_packets": 1,
  "connections": [
    {
      "generation_id": 1,
      "endpoints": {
        "initiator": {"ip": "10.0.0.1", "port": 12345},
        "responder": {"ip": "10.0.0.2", "port": 80}
      },
      "close_reason": "fin",
      "first_packet": 3,
      "last_packet": 15,
      "initiator_to_responder": {
        "syn_packet": 3,
        "known_intervals": [[0, 20]],
        "gaps": [[20, 30]],
        "conflicts": [{"start": 15, "end": 20, "packets": [7, 8]}],
        "source_packets": [6, 7, 8, 9, 10],
        "fin_packet": 13
      },
      "responder_to_initiator": { "...": "..." }
    }
  ]
}
```

- `close_reason`：`fin`（双向 FIN 完成）、`rst`（任一方向 RST 关闭）、
  `null`（被新 SYN 取代且未关闭）
- `known_intervals`/`gaps`：半开区间 `[start, end)`，偏移以**本方向自身 SYN 之后
  首字节**为 0；SYN/FIN 占序号但不输出。缺口末端到 FIN 所在位置或最大载荷末端，
  不补零
- `conflicts`：重叠但字节不一致的区间与相关包号（包号为文件中的记录序号，
  从 1 开始），保留文件中先到的字节，不按时间戳改写
- `source_packets`：向该方向贡献过载荷的包号（含重传）
- `skipped`：按原因计数（非 IPv4 以太网类型、非 TCP、IPv4 分片、VLAN）
- `missing_syn_packets`：活动代缺失起始 SYN 的孤立 TCP 包计数，不混入连接

### `GET /captures/{capture_id}/generations/{generation_id}/bytes`

按偏移下载重组后的原始字节（`application/octet-stream`）。

查询参数：

- `direction`：`c2s`（发起方→响应方）或 `s2c`
- `offset`：非负整数，方向内字节偏移
- `length`：正整数，最大 8 MiB

结果：

- `200`：区间全部落在已知区间内，返回字节
- `409 Conflict`：区间任意部分跨越缺口，拒绝返回（不补零、不拼接）
- `404`：capture/generation/direction 不存在

## 分代与重组规则

- 连接键为**无序**端点四元组，两个方向归并到同一连接
- 不带 ACK 的 SYN 开启新一代；活动代内同序号 SYN 视为重传，新序号 SYN
  或连接已关闭（FIN/RST）后的 SYN 创建新一代
- 对端 SYN,ACK 确定另一方向的序号基准；支持 32 位序号回绕（mod 2³²）
- 乱序片段按序号归位，部分重叠按字节裁剪；相同重传去重，冲突区间保留
  文件中先到内容并记录冲突区间及两侧包号
- FIN 双向到齐标记 `fin`；任一方向 RST 标记 `rst`；关闭后的报文不计入任何代

## 限制

- 上传 50 MiB（`app/service.py: MAX_UPLOAD`）
- 每份 PCAP 最多 200 代连接（`MAX_GENERATIONS`），超限整份拒绝
- 每方向重组跨度 8 MiB（`MAX_SPAN`），超限整份拒绝
- 仅处理 Ethernet 内未分片 IPv4/TCP；其余跳过计数

## 持久化与并发

- 每次成功导入先写 `<id>.tmp`（`O_EXCL`，同步刷盘），再原子 `rename` 为
  `<id>.json`；只有提交成功才可查询
- 失败清理临时文件；`id` 使用 UUID，并发上传互不覆盖
- 文档为不可变 JSON（载荷片段 base64 存储），服务重启后直接扫目录可读

## 模块结构

- `app/pcap_reader.py`：抓包读取（大小端、微秒/纳秒、截断校验、跳过计数）
- `app/reassembler.py`：连接分代、32 位回绕、字节重组、冲突、缺口、区间读取
- `app/storage.py`：原子持久化仓储
- `app/service.py`：导入流水线（限制、事务式提交）
- `app/main.py`：FastAPI 上传/查询/区间下载
- `scripts/generate_sample.py`：生成含乱序/重传/冲突/缺口/FIN/RST/跳过报文的示例

## 自测

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q app scripts tests
```

覆盖：大小端与微/纳秒解析、容器与报文截断、乱序/重叠/冲突去重、32 位回绕、
SYN 分代、FIN/RST 关闭、孤立包计数、200 代与 8 MiB 限制、HTTP 上传/查询/200/400/
404/409/413、以及重启后持久化可读。

## curl 示例

```bash
# 导入
curl -F 'file=@sample_capture.pcap;type=application/vnd.tcpdump.pcap' \
  http://127.0.0.1:8000/captures

# 查询
curl -s http://127.0.0.1:8000/captures/$CID | python -m json.tool

# 下载已重组的 20 字节（首个方向）
curl "http://127.0.0.1:8000/captures/$CID/generations/1/bytes?direction=c2s&offset=0&length=20"

# 跨缺口 -> 409
curl -i "http://127.0.0.1:8000/captures/$CID/generations/1/bytes?direction=c2s&offset=15&length=10"
```
