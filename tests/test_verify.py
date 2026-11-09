import gzip
import io
import tarfile
from pathlib import Path

import pytest

from evidence_pack.errors import EvidenceInvalid, UsageError
from evidence_pack.packer import PackOptions, pack
from evidence_pack.verifier import VerifyOptions, verify


def _packed(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.txt").write_text("original")
    # 这些用例验的是「无签名时只有包外锚点才算证据」，所以显式关掉签名。
    result = pack(
        PackOptions(
            repo_root=repo,
            out_dir=tmp_path / "out",
            includes=["src"],
            sbom="none",
            collect_git=False,
            sign=False,
        )
    )
    return Path(result.bundle_path)


def _evil(tmp_path: Path, members) -> Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for m in members:
            tar.addfile(m, io.BytesIO(b"x") if m.isfile() else None)
    out = tmp_path / "evil.tar.gz"
    with gzip.GzipFile(filename="", mode="wb", fileobj=open(out, "wb"), mtime=0) as gz:
        gz.write(buf.getvalue())
    return out


def test_manifest_only_bundle_is_not_accepted_as_evidence(tmp_path, monkeypatch):
    bundle = _packed(tmp_path, monkeypatch)
    with pytest.raises(EvidenceInvalid, match="不构成证据"):
        verify(VerifyOptions(bundle_path=bundle))


def test_anchor_makes_bundle_meaningful(tmp_path, monkeypatch):
    bundle = _packed(tmp_path, monkeypatch)
    sha = __import__("hashlib").sha256(bundle.read_bytes()).hexdigest()
    result = verify(VerifyOptions(bundle_path=bundle, expect_sha256=sha))
    assert result.anchored and result.manifest_verified


def test_wrong_anchor_fails(tmp_path, monkeypatch):
    bundle = _packed(tmp_path, monkeypatch)
    with pytest.raises(EvidenceInvalid, match="锚点不符"):
        verify(VerifyOptions(bundle_path=bundle, expect_sha256="a" * 64))


def test_bad_anchor_format_is_usage_error(tmp_path, monkeypatch):
    bundle = _packed(tmp_path, monkeypatch)
    with pytest.raises(UsageError):
        verify(VerifyOptions(bundle_path=bundle, expect_sha256="not-a-hash"))


def test_forged_bundle_with_recomputed_manifest_is_caught_by_anchor(
    tmp_path, monkeypatch
):
    bundle = _packed(tmp_path, monkeypatch)
    real_sha = __import__("hashlib").sha256(bundle.read_bytes()).hexdigest()

    work = tmp_path / "forge"
    work.mkdir()
    with tarfile.open(bundle, "r:gz") as tar:
        tar.extractall(work, filter="data")
    (work / "artifacts" / "src" / "a.txt").write_text("FORGED")
    lines = []
    for p in sorted(work.rglob("*")):
        if p.is_file() and p.name != "sha256sum.txt":
            import hashlib

            rel = p.relative_to(work).as_posix()
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}")
    (work / "manifest" / "sha256sum.txt").write_text("\n".join(lines) + "\n")

    forged = tmp_path / "forged.tar.gz"
    with tarfile.open(forged, "w:gz") as tar:
        for p in sorted(work.iterdir()):
            tar.add(p, arcname=p.name)

    # manifest 自洽，但没有外部锚点时必须是"无效"
    with pytest.raises(EvidenceInvalid):
        verify(VerifyOptions(bundle_path=forged))
    # 拿真实原始锚点核对，必须被抓
    with pytest.raises(EvidenceInvalid, match="锚点不符"):
        verify(VerifyOptions(bundle_path=forged, expect_sha256=real_sha))


@pytest.mark.parametrize("kind", ["absolute", "traversal", "symlink", "hardlink"])
def test_malicious_tar_is_rejected(tmp_path, kind):
    m = tarfile.TarInfo(
        {
            "absolute": "/etc/passwd",
            "traversal": "../x",
            "symlink": "link",
            "hardlink": "hlink",
        }[kind]
    )
    if kind in ("symlink", "hardlink"):
        m.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
        m.linkname = "/etc/passwd"
        m.size = 0
    else:
        m.size = 1
    evil = _evil(tmp_path, [m])
    import hashlib

    sha = hashlib.sha256(evil.read_bytes()).hexdigest()
    with pytest.raises(EvidenceInvalid):
        verify(VerifyOptions(bundle_path=evil, expect_sha256=sha))


def test_missing_bundle_is_usage_error(tmp_path):
    with pytest.raises(UsageError, match="不存在"):
        verify(VerifyOptions(bundle_path=tmp_path / "nope.tar.gz"))


def _packed_with_remote(tmp_path: Path, monkeypatch, remote: str) -> Path:
    """打一个有 git 元数据的包，remote 地址由参数决定。"""
    import subprocess

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.txt").write_text("original")
    for args in (
        ["init", "-q"],
        ["config", "user.email", "t@example.com"],
        ["config", "user.name", "t"],
        # 夹具造的仓库没有签名私钥；本仓库 / 开发镜像常全局开着 commit.gpgsign，
        # 不关掉就会在 git commit 里撞上 "gpg failed to sign the data"。
        ["config", "commit.gpgsign", "false"],
        ["add", "-A"],
        ["commit", "-qm", "init"],
        ["remote", "add", "origin", remote],
    ):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    result = pack(
        PackOptions(
            repo_root=repo,
            out_dir=tmp_path / "out",
            includes=["src"],
            sbom="none",
            sign=False,
        )
    )
    return Path(result.bundle_path)


def test_expect_repo_matches_recorded_remote(tmp_path, monkeypatch):
    bundle = _packed_with_remote(
        tmp_path, monkeypatch, "https://github.com/acme/app.git"
    )
    sha = __import__("hashlib").sha256(bundle.read_bytes()).hexdigest()
    result = verify(
        VerifyOptions(bundle_path=bundle, expect_sha256=sha, expect_repo="acme/app")
    )
    assert result.anchored
    assert result.anchor_warnings == []


def test_expect_repo_mismatch_is_invalid(tmp_path, monkeypatch):
    """包内记的仓库和期望的不一样 —— 这是真的对不上，必须判 2。"""
    bundle = _packed_with_remote(
        tmp_path, monkeypatch, "https://github.com/evil/app.git"
    )
    with pytest.raises(EvidenceInvalid, match="锚点不符"):
        verify(VerifyOptions(bundle_path=bundle, expect_repo="acme/app"))


def test_expect_repo_without_remote_metadata_is_not_tampering(tmp_path, monkeypatch):
    """包内没有 remote（checkout 的默认形态）不是篡改证据。

    这里曾经判 2：Action 默认把 github.repository 塞进 --expect-repo，
    而 actions/checkout 检出的工作区 remote 是空的，于是每个没配 remote
    的仓库第一次跑就红。缺元数据是采集环境的问题，不该记在证据头上。
    """
    bundle = _packed(tmp_path, monkeypatch)  # collect_git=False，包里根本没有 git.json
    sha = __import__("hashlib").sha256(bundle.read_bytes()).hexdigest()
    result = verify(
        VerifyOptions(bundle_path=bundle, expect_sha256=sha, expect_repo="acme/app")
    )
    assert result.ok and result.exit_code == 0
    # sha 锚点照样生效，但 repo 这条锚点没起作用，必须说出来。
    assert result.anchored
    assert len(result.anchor_warnings) == 1
    assert "未生效" in result.anchor_warnings[0]


def test_expect_repo_without_anchor_still_requires_trust_root(tmp_path, monkeypatch):
    """没有 remote 元数据不等于放行：没有包外锚点照样是「不构成证据」。"""
    bundle = _packed(tmp_path, monkeypatch)
    with pytest.raises(EvidenceInvalid, match="不构成证据"):
        verify(VerifyOptions(bundle_path=bundle, expect_repo="acme/app"))
