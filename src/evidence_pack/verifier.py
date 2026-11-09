"""验证据包。

校验顺序是按「攻击者最容易做到的排前面」：
  1. 外层锚点（调用方给的 --expect-sha256 / --expect-repo）——最便宜也最硬
  2. 签名（如果给了 bundle）——真正的信任根
  3. 内部 manifest——只能证明"包里自洽"，没有上面两条等于零信息量

第 3 条单独拿出来说：manifest 和内容躺在同一个包里，谁都能重算。
所以 manifest 通过**不构成**证据有效的充分条件：
调用方没给签名也没给锚点时，结论只能是 `anchored: false`，
绝不能是「验证通过」。
"""

from __future__ import annotations

import json
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .errors import EvidenceError, EvidenceInvalid, ToolFailure, UsageError
from .fsutil import sha256_file
from .signing import SignatureResult
from .signing import verify as verify_signature

MAX_UNPACKED_BYTES = 4 * 1024 * 1024 * 1024  # 4 GiB，防解压炸弹


@dataclass
class VerifyOptions:
    """验包参数。

    `exit_code_only` 是给 Action 用的「只看结论」模式：不抛异常，把判定结果
    原样带出来（含 error），退出码仍由调用方按 errors.py 的三档决定。
    注意这只是**输出形态**的差别，判定本身一秒都没有放宽。
    """

    bundle_path: Path
    signature_bundle: Path | None = None
    identity: str | None = None
    issuer: str | None = None
    ignore_tlog: bool = False
    expect_sha256: str | None = None
    expect_repo: str | None = None
    exit_code_only: bool = False


@dataclass
class VerifyResult:
    """校验结论。ok / exit_code 按 errors.py 的三档语义给出，不许混。"""

    bundle_path: str
    bundle_sha256: str
    ok: bool = True
    exit_code: int = 0
    error: str | None = None
    error_kind: str | None = None
    manifest_verified: bool = False
    anchored: bool = False
    file_count: int = 0
    repo: str | None = None
    source_date_epoch: int | None = None
    signature: SignatureResult = field(default_factory=SignatureResult)
    # 锚点没能真正核对时留话（不是失败，是「这条锚点没起作用」），
    # 好让人知道 anchored=true 到底靠的是什么。
    anchor_warnings: list[str] = field(default_factory=list)


def safe_extract(bundle_path: Path, dest: Path) -> None:
    """只接受普通文件和目录。

    绝对路径、`..` 穿越、符号链接、硬链接、设备文件一律拒绝——
    证据包是别人给你的，解包环节本身就是攻击面。
    """
    total = 0
    try:
        tar = tarfile.open(bundle_path, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ToolFailure(f"bundle 不是合法的 tar.gz：{exc}") from exc

    with tar:
        for member in tar.getmembers():
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise EvidenceInvalid(f"bundle 内含越界路径：{member.name}")
            if member.issym() or member.islnk():
                raise EvidenceInvalid(f"bundle 内含链接（篡改风险）：{member.name}")
            if not (member.isfile() or member.isdir()):
                raise EvidenceInvalid(f"bundle 内含非常规文件类型：{member.name}")
            total += member.size
            if total > MAX_UNPACKED_BYTES:
                raise EvidenceInvalid("bundle 解压后体积超限，疑似解压炸弹。")
            # filter="data"：3.14 起是默认值，这里显式写出来，保证 3.13/3.14
            # 行为一致，也再多一层防线（上面的检查已拒绝越界路径、链接和特殊文件）。
            tar.extract(member, path=dest, set_attrs=False, filter="data")


def _read_manifest(root: Path) -> dict[str, str]:
    path = root / "manifest" / "sha256sum.txt"
    if not path.is_file():
        raise EvidenceInvalid("bundle 缺少 manifest/sha256sum.txt。")
    expected: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, rel = line.partition("  ")
        if not rel:
            raise EvidenceInvalid(f"manifest 行格式非法：{line!r}")
        expected[rel] = digest
    return expected


def check_manifest(root: Path) -> int:
    """逐条比对 sha256sum.txt，返回被校验的文件数。

    发现任何不一致（未声明文件 / 文件缺失 / 哈希不符）一律抛
    EvidenceInvalid，不做「部分通过」：证据包只有全绿与不成立两种结局。
    这只能证明包内自洽：清单本身也在包里，改包的人顺手就能改它。
    真正的信任根必须在包外，这里不做也不假装做那件事。
    """
    expected = _read_manifest(root)
    manifest_rel = "manifest/sha256sum.txt"

    found: dict[str, Path] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel == manifest_rel:
            continue
        found[rel] = path

    unexpected = sorted(set(found) - set(expected))
    if unexpected:
        raise EvidenceInvalid(
            f"bundle 含 manifest 未声明的文件：{', '.join(unexpected)}"
        )

    missing = sorted(set(expected) - set(found))
    if missing:
        raise EvidenceInvalid(f"manifest 声明的文件缺失：{', '.join(missing)}")

    for rel, digest in sorted(expected.items()):
        actual = sha256_file(found[rel])
        if actual != digest:
            raise EvidenceInvalid(
                f"哈希不符：{rel}（manifest {digest}，实际 {actual}）"
            )
    return len(expected)


def _strip_comment(sha: str) -> str:
    return sha.split("#", 1)[0].strip().lower()


def _anchor(result: VerifyResult, opts: VerifyOptions, root: Path) -> None:
    if opts.expect_sha256:
        want = _strip_comment(opts.expect_sha256)
        if len(want) != 64 or any(c not in "0123456789abcdef" for c in want):
            raise UsageError(
                f"--expect-sha256 不是 64 位十六进制：{opts.expect_sha256!r}"
            )
        actual = result.bundle_sha256
        if want != actual:
            raise EvidenceInvalid(f"锚点不符：期望 {want}，实际 {actual}")
        result.anchored = True

    if opts.expect_repo:
        want_repo = opts.expect_repo.strip()
        # 优先用 git remote：那是仓库自己的身份。
        # run.json 里的 repository 字段来自 runner 环境变量，任何人 export 一下就能改，
        # 只能作为"两者是否一致"的佐证，不能独自充当锚点。
        recorded = _recorded_remote(root)
        if not recorded:
            # 「包内没有 remote 元数据」是采集环境的问题，不是篡改的证据：
            # actions/checkout 的检出默认带着空的 remote，本地打包、剥离 .git
            # 的构建上下文同理。把它判成 2，等于让所有没配 remote 的仓库
            # 第一次跑就红 —— 那是把工具的限制冒充成对方的罪名。
            # 所以只报告这条锚点未生效，让它退化成「未锚定」，由上层决定收不收。
            result.anchor_warnings.append(
                f"--expect-repo 未生效：包内没有 git remote 信息，无法核对 "
                f"{want_repo}（这不等于证据无效，但这条锚点没起作用）"
            )
        else:
            normalized = recorded.rstrip("/").removesuffix(".git")
            if not (normalized == want_repo or normalized.endswith("/" + want_repo)):
                raise EvidenceInvalid(
                    f"锚点不符：期望仓库 {want_repo}，包内记录 {recorded}"
                )
            result.anchored = True


def _recorded_remote(root: Path) -> str | None:
    """读包内记下的 git remote 地址；没有或读不动都返回 None。"""
    git_json = root / "metadata" / "git.json"
    if not git_json.is_file():
        return None
    try:
        return (
            json.loads(git_json.read_text(encoding="utf-8")).get("remote_url") or None
        )
    except json.JSONDecodeError:
        return None


def read_binding(root: Path) -> dict | None:
    """读包内声明的期望签名身份（打包方写的期望值，不是信任根）。"""
    path = root / "metadata" / "binding.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _read_run_meta(root: Path) -> tuple[str | None, int | None]:
    run_file = root / "metadata" / "run.json"
    meta_file = root / "metadata" / "metadata.json"
    repo = None
    epoch = None
    if run_file.is_file():
        try:
            run = json.loads(run_file.read_text(encoding="utf-8"))
            repo = (
                run.get("github_repository")
                or run.get("cnb_repo_slug")
                or run.get("gitlab_project_path")
            )
        except json.JSONDecodeError:
            pass
    if meta_file.is_file():
        try:
            epoch = json.loads(meta_file.read_text(encoding="utf-8")).get(
                "source_date_epoch"
            )
        except json.JSONDecodeError:
            pass
    return repo, epoch


def _verify_once(opts: VerifyOptions) -> VerifyResult:
    bundle_path = opts.bundle_path
    if not bundle_path.is_file():
        raise UsageError(f"bundle 不存在：{bundle_path}")

    result = VerifyResult(
        bundle_path=str(bundle_path), bundle_sha256=sha256_file(bundle_path)
    )

    with tempfile.TemporaryDirectory(prefix="evidence-verify-") as tmp:
        root = Path(tmp)
        safe_extract(bundle_path, root)
        result.file_count = check_manifest(root)
        result.manifest_verified = True
        result.repo, result.source_date_epoch = _read_run_meta(root)

        # 签名的对象必须是**这份文件本身**，所以验签对着原始路径做，与解包互不影响。
        # 解包先做是为了能读到包内声明的期望身份（调用方没显式给时用它兜底）。
        if opts.signature_bundle:
            if not opts.signature_bundle.is_file():
                raise UsageError(f"签名 bundle 不存在：{opts.signature_bundle}")
            result.signature = verify_signature(
                bundle_path,
                opts.signature_bundle,
                identity=opts.identity,
                issuer=opts.issuer,
                ignore_tlog=opts.ignore_tlog,
                binding=read_binding(root),
            )

        _anchor(result, opts, root)

    if not result.anchored and not result.signature.verified:
        # 只有包内自洽 = 零信息量。判定必须如实反映，不能报"通过"。
        raise EvidenceInvalid(
            "manifest 自洽，但既无签名也无外部锚点（--expect-sha256 / --expect-repo）："
            "这种包的哈希可以随手重算，不构成证据。"
        )
    return result


def verify(opts: VerifyOptions) -> VerifyResult:
    """验包。`exit_code_only` 时把失败也变成结构化结果返回，不抛异常。"""
    if not opts.exit_code_only:
        return _verify_once(opts)
    try:
        return _verify_once(opts)
    except EvidenceError as exc:
        # 失败也要带上已算出的 sha256：Action 里还要把它当锚点/台账登记。
        try:
            digest = sha256_file(opts.bundle_path)
        except OSError:
            digest = ""
        return VerifyResult(
            bundle_path=str(opts.bundle_path),
            bundle_sha256=digest,
            ok=False,
            exit_code=exc.exit_code,
            error=str(exc),
            error_kind=exc.kind,
        )
