# Packsmith · 可验证的离线数据集交付

将多文件数据集打成由内容寻址对象和**已认证 manifest** 组成的离线仓库。接收端可以区分三种情形——**数据本来就不同**（已认证快照之间的 changed/deleted 差异）、**对象在传输中坏了**（完整性错误，退出码 1）、**清单来自不受信任的发布者**（认证错误，退出码 3）——并在中断后继续恢复同一份可信快照。

## 信任模型

`Repository.resolve()` 是唯一的信任门，`load`、`verify`、`restore` 消费同一份 `TrustDecision`：不存在 verify 拒绝而 restore 仍写文件的路径。

- manifest 用 **HMAC-SHA256** 认证，密钥由调用方注入（`Repository(keys={...})`、`--key-file` 或 `PACKSMITH_KEY_FILE`），仓库目录从不保存密钥。
- MAC 输入是 manifest 的规范化 JSON（排序键、最紧凑分隔符），剔除 `mac.value` 但保留 `mac.alg` 与 `mac.keyid`：**算法、key id、metadata、文件路径、chunk 顺序及 base 身份都在覆盖范围内**。相同规范化输入必然产生相同认证结果，与文件的实际排版无关。
- **MAC 值编码规则**：32 字节 HMAC 输出的 64 个小写十六进制字符；大写、截断或其他编码一律视为格式错误。
- 未知算法、未知 key id、未注入对应密钥都是硬失败（`AuthenticationError`），**绝不退回普通 hash 接受**。
- 旧格式（format 1，无 MAC）只有显式 `allow_legacy` / `--allow-legacy` 策略才能读取，且永远报告 `authenticated: false`。

## 格式 v2

每个文件记录逻辑内容摘要（`sha256`）、声明大小（`size`）和有序 chunk 列表。每个 chunk 记录七个字段：

| 字段 | 含义 |
| --- | --- |
| `sha256` | 逻辑内容摘要（解码后明文的 SHA256） |
| `size` | 声明的逻辑大小（解码后字节数） |
| `codec` | `identity`（原始）或 `zlib`（标准库无损压缩） |
| `codec_version` | codec 合同版本，当前均为 1 |
| `encoded_sha256` | 编码对象摘要（仓库中存储对象的地址） |
| `encoded_size` | 编码对象声明大小 |

codec 注册表是独立边界：未知 codec 或版本直接拒绝，绝不跳过。`identity` chunk 的逻辑与编码摘要必须一致。对象读取按声明的 `encoded_size` 有界进行（超出即停）；解码按声明的 `size` 有界进行（zlib 用 `max_length` 把输出限制在声明大小 +1 以内，**压缩炸弹在有界内存中被拒绝，而不是先展开再发现**）；解码后再校验逻辑 hash，文件级联 hash 最后校验。

`snapshot --compress` 逐 chunk 尝试 zlib，仅在更小时存储压缩对象，因此同一文件可混合两种 codec。相同源、相同密钥与参数产生相同快照 id。

## 恢复会话

`restore` 在目标目录 `.packsmith/` 下维护会话：

- `session.json` 固定**快照身份、文件选择、metadata 要求和 codec 合同**。参数一致的续跑复用会话；**换了快照、文件选择或编码参数的续跑不得借用原会话状态**——报 `SessionConflictError`（退出码 4），除非显式 `--reset` 丢弃旧状态。
- `.part` 中间块按 chunk 重新校验逻辑 hash 后才复用，损坏的中间块被重新写入；文件完整校验通过后才原子 rename 到正式位置。rename 前进程退出不会留下看似成功的文件。
- `lock` 文件上的 flock 保证同一目标目录同一时刻只有一个恢复任务；竞争者得到 `RestoreBusyError`（退出码 4），两个进程不会把不同快照拼进一个交付结果。
- 成功返回的 `verified` 列表逐个给出选中文件的逻辑 hash 与大小，即交付证明；成功后清理会话状态。
- 恢复以单文件为原子单位，保留目标中未选中或不在快照内的已有文件，`deleted` 清单不会主动删除文件。需镜像结果时使用新的空目录。

## 运行

Python 3.11+，仅标准库。在项目目录执行：

```bash
export PYTHONPATH="$PWD/src"
python3 -c "import json; json.dump({'main': '<64 hex chars>'}, open('/tmp/keys.json', 'w'))"
python3 -m packsmith.cli --repo /tmp/packsmith-demo snapshot examples/dataset \
    --chunk-size 32 --compress --key-id main --key-file /tmp/keys.json
python3 -m unittest discover -s tests -v
python3 examples/smoke.py
```

保存返回的快照 ID 后可运行：

```bash
python3 -m packsmith.cli --repo /tmp/packsmith-demo verify SNAPSHOT_ID --key-file /tmp/keys.json
python3 -m packsmith.cli --repo /tmp/packsmith-demo inspect SNAPSHOT_ID --key-file /tmp/keys.json
python3 -m packsmith.cli --repo /tmp/packsmith-demo restore SNAPSHOT_ID /tmp/packsmith-out \
    --file schema.json --key-file /tmp/keys.json
python3 -m packsmith.cli --repo /tmp/packsmith-demo snapshot examples/dataset \
    --base SNAPSHOT_ID --key-id main --key-file /tmp/keys.json
```

`snapshot --metadata contract.json` 把 JSON 对象放入 manifest（被 MAC 覆盖）；`restore --require-metadata expected.json` 要求对应顶层键值完全相等，且在写任何文件之前检查。`restore --reset` 显式丢弃不兼容的中断会话。

## 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 成功 |
| 1 | 完整性失败：对象在传输/存储中损坏（`verify` 报告损坏文件与对象 SHA） |
| 2 | 用法或输入错误 |
| 3 | 认证失败：清单不来自受信任发布者（含未知算法/密钥、未授权的 legacy） |
| 4 | 目标目录被活动会话占用，或存在不兼容的中断会话 |

## 扩展接口

`formats.py` 定义规范化编码、路径契约、codec 注册表、MAC 与格式校验；`repository.py` 将信任门、对象存储、会话与文件适配分开；`cli.py` 负责操作入口与密钥注入。可以扩展对象存储、新 codec（注册新版本号）和传输模块。

```python
from packsmith import Repository

repo = Repository("package-store", keys={"main": key_bytes}, sign_with="main")
version = repo.snapshot("dataset", chunk_size=1024 * 1024, compress=True,
                        metadata={"schema_version": 2})
repo.restore(version, "restored", required_metadata={"schema_version": 2})
# 中断后重跑相同调用即续传；参数不同的续跑报 SessionConflictError。
```

## 一致性与边界

整个仓库目录（`chunks/` 和 `manifests/`）即交付物。增量对象仍依赖该仓库已有对象，不能只复制新 manifest；暂不提供跨仓库远程下载协议。目标目录须由单个恢复任务独占；flock 防御协作进程间的竞争，不防御不受信任进程并发替换祖先目录的攻击。

源文件读取前后检查 inode/大小/mtime/ctime 和文件清单；这能发现常见并发变更，不保证多个文件处于同一事务时点。源应先由上游冻结。SHA256 证明内容完整性，HMAC 证明发布者身份；密钥分发不在本格式范围内。存储暂不自动回收孤立对象。文件模式、时间戳和空目录不在当前格式中。
