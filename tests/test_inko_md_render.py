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
    tables: list[str] = []

    def _split_row(line: str) -> list[str]:
        t = line.strip()
        if t.startswith("|"):
            t = t[1:]
        if t.endswith("|"):
            t = t[:-1]
        return [c.strip() for c in t.split("|")]

    def _is_sep(line: str) -> bool:
        cells = _split_row(line)
        return bool(cells) and all(re.fullmatch(r":?-{1,}:?", c or "") for c in cells)

    def _table_repl(m: re.Match[str]) -> str:
        lines = [ln.strip() for ln in m.group(0).strip().split("\n") if ln.strip()]
        if len(lines) < 2:
            return m.group(0)
        header = _split_row(lines[0])
        body_start = 2 if _is_sep(lines[1]) else 1
        rows = [_split_row(ln) for ln in lines[body_start:] if not _is_sep(ln)]
        if not header or not rows:
            return m.group(0)
        coln = len(header)

        def norm(row: list[str]) -> list[str]:
            r = row[:coln]
            while len(r) < coln:
                r.append("")
            return r

        th = "".join(f"<th>{c}</th>" for c in norm(header))
        trs = "".join(
            "<tr>" + "".join(f"<td>{c}</td>" for c in norm(r)) + "</tr>" for r in rows
        )
        i = len(tables)
        tables.append(
            f'<div class="md-table-wrap"><table class="md-table"><thead><tr>{th}</tr></thead>'
            f"<tbody>{trs}</tbody></table></div>"
        )
        return f"\x00TABLE{i}\x00\n\n"

    s = re.sub(r"(?:^[ \t]*\|.+\|[ \t]*\n){2,}", _table_repl, s, flags=re.M)
    parts = []
    for para in re.split(r"\n{2,}", s):
        p = para.strip()
        if not p:
            continue
        if re.match(r"^<(?:ul|ol|pre|h[1-4]|blockquote|div)", p):
            parts.append(p)
        elif re.fullmatch(r"\x00TABLE\d+\x00", p):
            parts.append(p)
        else:
            parts.append(f"<p>{p.replace(chr(10), '<br>')}</p>")
    s = "".join(parts)
    s = re.sub(r"\x00TABLE(\d+)\x00", lambda m: tables[int(m.group(1))], s)
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


def test_gfm_table_renders() -> None:
    md = (
        "| What | Count |\n"
        "|------|-------|\n"
        "| Active beacons | 0 |\n"
        "| Total closed | 6 |\n"
    )
    out = render_markdown_safe(md)
    assert '<table class="md-table">' in out
    assert "<th>What</th>" in out
    assert "<th>Count</th>" in out
    assert "<td>Active beacons</td>" in out
    assert "<td>0</td>" in out
    assert "|------|" not in out
