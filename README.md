# PTPv2 双步交换审计服务

精密授时实验室对主时钟 / 从时钟 IEEE 1588-2008（PTPv2）双步端到端延迟交换
进行复核的 HTTP 服务。按捕获顺序提交 1–1000 条原始报文，服务解析
`Sync` / `Follow_Up` / `Delay_Req` / `Delay_Resp`，按端口身份与 16 位序号配对
完整四步交换，输出整数分子（分母固定为 **131072 纳秒**）的时钟偏移与平均路径
时延裁决；任何序号回绕混叠、重复冲突、孤立响应、乱序阶段、未闭合交换或负路径
时延都会被整体拒绝，不输出任何部分结果。

## 快速启动（Docker Compose）

```bash
cp .env.example .env          # 设置宿主机端口 PTP_API_HOST_PORT，默认 8080
docker compose up -d --build  # 健康检查通过后在该端口提供 API
curl -s http://localhost:8080/health
```

一次性验证服务（代码测试 + 应用构建检查 + 真实 API 冒烟），以退出码报告结果：

```bash
docker compose up --build verify   # 退出码 0 表示全部通过
```

`verify` 服务通过 `depends_on: condition: service_healthy` 仅在 API 健康检查成功
后启动；它执行 `scripts/verify.sh`：

1. `compileall` 与 `import app.main`（应用构建检查）；
2. `pytest`（47 个解析/状态机/HTTP 测试）；
3. `scripts/smoke.py`（一组完整交换的端到端 API 冒烟，含负例）。

## 接口

### `POST /api/ptp/exchanges/audit`

```json
{
  "captures": [
    {"packet": "<base64 原始 PTP 报文>", "direction": "in",  "localTimestampNs": 1000000100},
    {"packet": "<base64>",               "direction": "in",  "localTimestampNs": 1000000000},
    {"packet": "<base64>",               "direction": "out", "localTimestampNs": 2000000000},
    {"packet": "<base64>",               "direction": "in",  "localTimestampNs": 2000000140}
  ]
}
```

`direction`：`in` = Sync / Follow_Up / Delay_Resp（从端口侧入站），
`out` = Delay_Req（从端口侧出站）。

成功响应（按交换 **完成顺序** 排列）：

```json
{
  "count": 1,
  "denominatorNs": 131072,
  "exchanges": [
    {
      "sequenceId": 1234,
      "masterPortIdentity": {"clockIdentity": "0011223344556677", "portNumber": 1},
      "slavePortIdentity":  {"clockIdentity": "AABBCCDDEEFF0011", "portNumber": 2},
      "domainNumber": 0,
      "offsetFromMasterNumerator": -2621420,
      "meanPathDelayNumerator": 15728620,
      "correctionFieldSum": 20,
      "denominatorNs": 131072,
      "syncCaptureIndex": 0,
      "completedAtCaptureIndex": 3
    }
  ]
}
```

错误响应（稳定错误码 + 首个相关捕获项，0 基 `captureIndex` 与 1 基
`capturePosition` 同时给出）：

```json
{"error": {"code": "ORPHAN_MESSAGE", "message": "...", "captureIndex": 4, "capturePosition": 5}}
```

## 配对与裁决规则

* 交换键为 `(masterPortIdentity, slavePortIdentity, sequenceId)`：
  Sync/Follow_Up 以头部源端口标识主时钟；Delay_Req 以头部源端口标识请求从时钟；
  Delay_Resp 以头部源端口标识主时钟、以报体内 `requestingPortIdentity` 标识从
  时钟，从而在多主/多从场景下无歧义闭合。同一条 Sync/Follow_Up 流可被多个从
  端口的 Delay 支路复用（多播语义）。
* 阶段必须严格按 `Sync → Follow_Up → Delay_Req → Delay_Resp` 到达；孤立响应与
  乱序阶段分别返回 `ORPHAN_MESSAGE` / `OUT_OF_ORDER_STAGE`。
* 同一去重键的 **逐字节相同** 重传允许且不改变状态；同键不同字节返回
  `CONFLICTING_MESSAGE`。因此一批捕获内 16 位序号回绕后若报文非完全相同必然
  冲突，序号混叠无法掩盖异常链路。
* Sync 必须置 `twoStepFlag`，否则返回 `NON_TWO_STEP_MESSAGE`。
* 批处理结束时任何未闭合交换 / 未应答的 Delay_Req 均返回 `UNCLOSED_EXCHANGE`。

## 整数运算

记 `A = t2 - t1`、`B = t4 - t3`（整数纳秒），`C` 为四类报文 **有符号**
`correctionField` 之和（PTP 单位 1/65536 ns）：

```
offsetFromMasterNumerator = (A - B) * 65536 + C
meanPathDelayNumerator    = (A + B) * 65536 - C
```

两者均为分母 `131072 ns` 的整数分子；`meanPathDelayNumerator < 0` 返回
`NEGATIVE_PATH_DELAY`。

## 错误码

| HTTP | code | 含义 |
| --- | --- | --- |
| 400 | `INVALID_REQUEST` / `INVALID_BASE64` / `MALFORMED_PACKET` | 请求或报文格式非法 |
| 422 | `UNSUPPORTED_MESSAGE_TYPE` | 非四类报文 |
| 422 | `NON_TWO_STEP_MESSAGE` | Sync 未置 twoStepFlag |
| 422 | `DIRECTION_MISMATCH` | 报文方向与四步角色不符 |
| 422 | `ORPHAN_MESSAGE` | 缺少前置报文的孤立响应 |
| 422 | `OUT_OF_ORDER_STAGE` | 阶段乱序 |
| 422 | `CONFLICTING_MESSAGE` | 同键不同字节 / 域或身份冲突 |
| 422 | `NEGATIVE_PATH_DELAY` | 平均路径时延分子为负 |
| 422 | `UNCLOSED_EXCHANGE` | 交换缺少阶段或 Delay_Req 无响应 |

## 本地无容器开发

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --port 8000
pytest
API_BASE_URL=http://127.0.0.1:8000 python scripts/smoke.py
```
