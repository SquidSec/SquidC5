"""Release CI still stages Raspberry Pi (linux-arm64) assets when present."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


def test_binaries_jobs_are_self_hosted() -> None:
    # Linux and Windows builds are separate jobs (they were a matrix before the
    # release path stopped round-tripping Windows binaries through an artifact).
    assert "self-hosted, Linux, X64, squidsec" in CI
    assert "self-hosted, Windows, X64, squidsec" in CI
    assert "name: binaries (linux-x64)" in CI
    assert "name: binaries (windows-x64)" in CI


def test_upload_failures_are_fatal() -> None:
    # A silent artifact upload failure once published a release with no Windows
    # assets, so no artifact upload may swallow errors.
    blocks = CI.split("- uses: actions/upload-artifact")
    assert len(blocks) > 1, "expected at least one upload-artifact step"
    for block in blocks[1:]:
        step = block.split("- name:")[0]
        assert "continue-on-error" not in step
    assert "if-no-files-found: error" in CI


def test_windows_assets_published_by_windows_job() -> None:
    # Windows binaries attach to the existing release rather than via artifact.
    assert "Upload to GitHub Release" in CI
    assert "release/sc5-windows-x64.exe" in CI
    assert "release/squidc5-windows-x64.exe" in CI


def test_github_release_publishes_linux_arm64_assets() -> None:
    assert "sc5-linux-arm64" in CI
    assert "squidc5-linux-arm64" in CI
    assert "release/sc5-linux-arm64" in CI
    assert "release/squidc5-linux-arm64" in CI
