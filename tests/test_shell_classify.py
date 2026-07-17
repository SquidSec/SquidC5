from squidc5.shells.classify import classify_inbound
from squidc5.shells.stabilize import ShellStabilizer, detect_os


def test_reject_tls_clienthello():
    # Sample from user's false shell (TLS record type 0x16 version 0x0302)
    tls = bytes.fromhex("160302016f0100016b0303") + b"RHx" + b"\x00" * 40
    v = classify_inbound(tls)
    assert v.is_shell is False
    assert "tls" in v.reason


def test_reject_http_probe():
    v = classify_inbound(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert v.is_shell is False
    assert v.reason == "http_probe"


def test_accept_shell_text():
    v = classify_inbound(b"bash-5.1$ whoami\nroot\n")
    assert v.is_shell is True


def test_accept_stable_banner():
    v = classify_inbound(b"SC5_STABLE_LINUX\n")
    assert v.is_shell is True


def test_accept_empty_pending():
    v = classify_inbound(b"")
    assert v.is_shell is True  # indeterminate — wait for probe


def test_detect_os_linux():
    assert detect_os("SC5_OS=Linux\n") == "linux"


def test_detect_os_windows():
    assert detect_os("SC5_OS=Windows_NT\nMicrosoft Windows") == "windows"


def test_stabilizer_plans():
    s = ShellStabilizer("1.2.3.4", 443)
    linux = s.plan("linux")
    assert linux.os_family == "linux"
    assert any("base64" in c or "python" in c for c in linux.commands)
    assert "SC5_PING" in __import__("squidc5.shells.stabilize", fromlist=["linux_stage2_script"]).linux_stage2_script("1.2.3.4", 443)
    win = s.plan("windows")
    assert win.os_family == "windows"
    assert any("powershell" in c.lower() for c in win.commands)
    # unknown defaults to linux (avoid dual-inject storms)
    unk = s.plan("unknown")
    assert unk.os_family == "linux"
