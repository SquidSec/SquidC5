"""Release CI must publish Raspberry Pi (linux-arm64) binaries."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


def test_binaries_matrix_includes_linux_arm64() -> None:
    assert "ubuntu-24.04-arm" in CI
    assert "artifact: linux-arm64" in CI


def test_github_release_publishes_linux_arm64_assets() -> None:
    assert "sc5-linux-arm64" in CI
    assert "squidc5-linux-arm64" in CI
    assert "release/sc5-linux-arm64" in CI
    assert "release/squidc5-linux-arm64" in CI
