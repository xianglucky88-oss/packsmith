# Packsmith · 可恢复数据集交付

将多文件数据集打成由内容寻址对象和完整 manifest 组成的离线仓库。接收方可以检查契约、定位损坏块、选择文件恢复，并在中断后复用已校验的部分。

## 已实现

- 逐文件流式读取、固定字节分块、SHA256 内容去重与完整文件校验。
- manifest 按内容寻址，包含全量文件清单、基础快照引用、变化/删除清单和自定义 schema 元数据。
- 增量快照共享未变化对象；恢复时按新快照完整清单重建，无需逐条重放差异。
- 恢复前按要求的元数据键值检查兼容性；支持只恢复选定文件。
- 已下载中间块逐块重新校验，损坏中间块重新写入；完成一个文件后原子替换正式文件。
- `verify` 返回损坏文件和对象 SHA；校验失败退出码为 1，输入错误为 2。
- 拒绝路径穿越、源符号链接及恢复目录内的符号链接。

## 运行

Python 3.11+。在项目目录执行：

```bash
export PYTHONPATH="$PWD/src"
python3 -m packsmith.cli --repo /tmp/packsmith-demo snapshot examples/dataset --chunk-size 32
python3 -m unittest discover -s tests -v
python3 examples/smoke.py
```

保存返回的快照 ID 后可运行：

```bash
python3 -m packsmith.cli --repo /tmp/packsmith-demo verify SNAPSHOT_ID
python3 -m packsmith.cli --repo /tmp/packsmith-demo inspect SNAPSHOT_ID
python3 -m packsmith.cli --repo /tmp/packsmith-demo restore SNAPSHOT_ID /tmp/packsmith-out --file schema.json
python3 -m packsmith.cli --repo /tmp/packsmith-demo snapshot examples/dataset --base SNAPSHOT_ID
```

`snapshot --metadata contract.json` 把 JSON 对象放入 manifest；`restore --require-metadata expected.json` 要求对应顶层键值完全相等。schema 文件也可以作为普通文件一起打包。运行 `examples/smoke.py` 会实际创建增量包、恢复比较字节、破坏对象并检查 CLI 错误状态。

## 扩展接口

`formats.py` 定义内容编码、路径契约和格式校验；`repository.py` 将业务流程与 `_read_chunk`、`_chunk_path`、`atomic_write` 文件适配分开；`cli.py` 负责操作入口。可以扩展对象存储、压缩、传输和签名模块。

```python
from packsmith import Repository

repo = Repository("package-store")
version = repo.snapshot("dataset", chunk_size=1024 * 1024,
                        metadata={"schema_version": 2})
def progress(name, completed_chunks):
    print(name, completed_chunks)

repo.restore(version, "restored", required_metadata={"schema_version": 2},
             progress=progress)
# 中断后重跑相同恢复调用。经校验的 .packsmith 中间块会被复用。
```

## 一致性与边界

整个仓库目录（`chunks/` 和 `manifests/`）即交付物。增量对象仍依赖该仓库已有对象，不能只复制新 manifest；暂不提供跨仓库远程下载协议。目标目录须由单个恢复任务独占，当前不防御不受信任进程并发替换祖先目录的攻击。

恢复以单文件为原子单位，保留目标中未选中或不在快照内的已有文件，`deleted` 清单不会主动删除这些文件。若需镜像结果，使用新的空目录。文件模式、时间戳和空目录不在当前格式中。

源文件读取前后检查 inode/大小/mtime/ctime 和文件清单；这能发现常见并发变更，不保证多个文件处于同一事务时点。源应先由上游冻结。SHA256 证明内容完整性，manifest 未签名，不提供发布者真实性。存储暂不自动回收孤立块。
