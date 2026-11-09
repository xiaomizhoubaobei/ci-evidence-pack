# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 仓库定位

`evidence-pack` 是一个 **GitHub Composite Action**，不是命令行工具。它把一次 CI 构建打成可独立验证的证据包：确定性 tar.gz + 严格 manifest + cosign keyless 签名 + 退出码 0/1/2/3 分层。

先读这三份文档，它们是契约而非背景材料：

- `AGENTS.md`：仓库协作规范（提交签名、编码规范、三条硬规矩）。
- `README.md`：面向使用者的行为契约、Action 输入输出、退出码、信任根边界。
- `docs-usage.md`：CNB / GitLab / 自托管环境接法与常见坑。

## 常用命令

```bash
# 开发环境（纯标准库运行时；dev 只多 pytest + PyYAML）
python3 -m pip install -e ".[dev]"

# 全量测试
PYTHONPATH=src python3 -m pytest -q

# 单文件 / 单用例 / 关键字
PYTHONPATH=src python3 -m pytest tests/test_verify.py -q
PYTHONPATH=src python3 -m pytest tests/test_verify.py::test_expect_repo_mismatch_is_invalid -q
PYTHONPATH=src python3 -m pytest tests/test_action.py -k oidc -q

# 代码门禁（black / flake8 / isort / mypy / pydocstyle）
pre-commit install
pre-commit run --all-files
pre-commit run black --all-files
```

`pytest.ini` 刻意只有 `[pytest]`：它的作用是让仓库根成为 pytest 的 rootdir；测试配置的唯一权威在 `pyproject.toml` 的 `[tool.pytest.ini_options]`。不要删掉它。

签名相关测试用假 `cosign`，不依赖网络和真实 Fulcio；`openssl` 只在部分证书窗口用例里可选使用。

## 架构

只有一个入口：`action.yml`。它调 `scripts/` 里的 shell 步骤，shell 再以 `python3 -m evidence_pack.action pack|verify|rekor` 调内核；参数全部走 `INPUT_*` 环境变量，结果以 JSON 写到 stdout。**不要再长出 CLI/参数解析/console_scripts**。

```text
action.yml
├─ 检查 python3 >= 3.13
├─ 按需安装 cosign / cyclonedx 扫描器
├─ scripts/action-pack.sh   → python -m evidence_pack.action pack
├─ scripts/action-anchor.sh → 把 bundle sha256 追加到包外台账
└─ scripts/action-verify.sh → python -m evidence_pack.action verify
```

内核模块分工：

- `src/evidence_pack/action.py`：读 `INPUT_*`，分发 `pack` / `verify` / `rekor`，把异常映射成退出码。
- `collect.py`：按 `include` / `exclude` 收集输入，保留仓库相对路径，记录被排除的 `skipped`。
- `fsutil.py`：确定性工具——排序、SHA-256、stable JSON、`SOURCE_DATE_EPOCH`、tarinfo 归一、gzip mtime=0。
- `packer.py`：组包布局（`artifacts/`、`metadata/`、`sbom/`、`manifest/`），生成 manifest，产出 tar.gz，按需签名。
- `sbom.py`：CycloneDX 生成；`auto` 模式拿不到时判 3；扫描器缺失时可按 `requirements.txt` / PEP 621 兜底。
- `signing.py`：cosign keyless 签名与验签；token 只走环境变量；检查 bundle 结构、digest binding、tlog、证书窗口。
- `verifier.py`：安全解包、manifest 全量校验、签名校验、包外锚点比对、信任根判定。
- `errors.py`：`UsageError` → 1，`EvidenceInvalid` → 2，`ToolFailure` → 3。

### pack 链路

`collect` → 暂存到 stage → 写 `metadata/{metadata,run,git}.json` → 生成 `sbom/sbom.cdx.json` → 写 `manifest/inputs.json` 和 `manifest/sha256sum.txt` → 确定性 tar.gz → cosign `sign-blob` 产出 `.sigstore.json`。

### verify 链路

`safe_extract` → `check_manifest`（缺失/额外/哈希不符都判 2）→ 有签名 bundle 则验签 → 锚点比对 → 最终要求 `anchored or signature.verified`，否则判 2。

## 必须保持的项目约束

- **信任根在包外**：`manifest/sha256sum.txt` 只证明包内自洽。没有签名、也没有真正的包外 `expect-sha256` 时，verify 必须判 2，不能因为“包内声明了仓库/身份”就放行。
- **退出码语义**：0 证据通过，1 用法错误，2 证据无效，3 工具异常。2 与 3 的人工处置完全不同；不要把网络/工具故障吞成 2，也不要在中间层改写退出码。
- **确定性**：时间统一取 `SOURCE_DATE_EPOCH`，文件/条目显式排序，tar 元数据归一，gzip mtime=0；不要依赖文件系统顺序或墙钟。改 `pack` 输出（文件集合、哈希、metadata 字段）必须同步更新确定性测试，必要时提升 `FORMAT_VERSION`。
- **签名只有 keyless**：没有长期私钥 fallback；token 只经环境变量（`SIGSTORE_ID_TOKEN` 等），禁止进 argv；identity/issuer 必须可核对。
- **安全解包**：拒绝绝对路径、`..`、符号链接/硬链接/特殊文件，并限制解压总量。打包侧也不要把仓库外的链接目标 dereference 进包。
- **不直接推主分支**：所有改动走 PR；提交信息用中文 Angular 格式（如 `fix(verify): 缺少外部锚点时判为不构成证据`）。

## 提交前

本仓库强制 GPG 签名。每次 `git commit` 前先跑：

```bash
bash install_gpg_keys.sh
```

提交后用 `git log -1 --format='%G?'` 确认是 `G` 或 `U`。任何一条 `N` 都不许 push；不要用 `--no-verify` 绕过 `pre-commit`。

## 测试组织

- `tests/test_action_entry.py`：`INPUT_*` → JSON 的入口契约。
- `tests/test_action.py`：shell 层输出、可复现性、OIDC 交换、退出码、示例 lint。
- `tests/test_verify.py`：manifest、锚点、恶意 tar、仓库匹配。
- `tests/test_keyless_oidc.py` / `test_signing.py`：token 传递、bundle 结构、证书窗口、假 cosign。
- `tests/test_collect.py` / `test_determinism.py` / `test_sbom.py`：收集规则、字节级确定性、SBOM 兜底与归一。

测试不应依赖真实 cosign、Rekor、Fulcio 或网络；需要外部命令时用 `monkeypatch` 把假程序放到 `PATH`。
