"""Safety properties for INKO client markdown rendering (mirrors ops-admin.js)."""

from __future__ import annotations

import html
import re


def _escape_html(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def render_markdown_safe(src: str) -> str:
    """Python mirror of web/ops-admin.js renderMarkdownSafe (subset for tests)."""
    s = str(src or "").replace("\r\n", "\n")
    fences: list[str] = []

    def fence_repl(m: re.Match[str]) -> str:
        lang, code = m.group(1), m.group(2)
        i = len(fences)
        lang_attr = f' class="language-{_escape_html(lang)}"' if lang else ""
        fences.append(f"<pre><code{lang_attr}>{_escape_html(code.rstrip(chr(10)))}</code></pre>")
        return f"\x00FENCE{i}\x00"

    s = re.sub(r"```([a-zA-Z0-9_-]*)\n?([\s\S]*?)```", fence_repl, s)
    s = _escape_html(s)
    s = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", s)
    s = re.sub(
        r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
        r'<a href="\2" target="_blank" rel="noopener noreferrer">\1</a>',
        s,
    )
    s = re.sub(r"^(#{1,4})\s+(.+)$", lambda m: f"<h{len(m.group(1))}>{m.group(2)}</h{len(m.group(1))}>", s, flags=re.M)
    s = re.sub(r"(\*\*|__)(?=\S)([\s\S]*?\S)\1", r"<strong>\2</strong>", s)
    s = re.sub(r"(\*|_)(?=\S)([\s\S]*?\S)\1", r"<em>\2</em>", s)
    parts = []
    for para in re.split(r"\n{2,}", s):
        p = para.strip()
        if not p:
            continue
        if re.match(r"^<(?:ul|ol|pre|h[1-4]|blockquote)", p):
            parts.append(p)
        else:
            parts.append(f"<p>{p.replace(chr(10), '<br>')}</p>")
    s = "".join(parts)
    s = re.sub(r"\x00FENCE(\d+)\x00", lambda m: fences[int(m.group(1))], s)
    return s


def test_raw_html_is_escaped() -> None:
    out = render_markdown_safe('<script>alert(1)</script> **bold**')
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "<strong>bold</strong>" in out


def test_fenced_code_escaped() -> None:
    out = render_markdown_safe("```js\n<script>x</script>\n```")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "<pre><code" in out


def test_link_http_only() -> None:
    out = render_markdown_safe("[x](https://example.com/a) [bad](javascript:alert(1))")
    assert 'href="https://example.com/a"' in out
    assert "href=\"javascript:" not in out
    assert "href='javascript:" not in out


def test_escape_html_helper() -> None:
    assert _escape_html("<a>") == html.escape("<a>", quote=True).replace("&#x27;", "&#39;")
