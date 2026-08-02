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

    def _cell_html(raw: str) -> str:
        c = _escape_html(raw)
        c = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", c)
        c = re.sub(r"(\*\*|__)(?=\S)([\s\S]*?\S)\1", r"<strong>\2</strong>", c)
        return c

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

        th = "".join(f"<th>{_cell_html(c)}</th>" for c in norm(header))
        trs = "".join(
            "<tr>" + "".join(f"<td>{_cell_html(c)}</td>" for c in norm(r)) + "</tr>" for r in rows
        )
        i = len(tables)
        tables.append(
            f'<div class="md-table-wrap"><table class="md-table"><thead><tr>{th}</tr></thead>'
            f"<tbody>{trs}</tbody></table></div>"
        )
        return f"\x00TABLE{i}\x00\n\n"

    s = re.sub(r"(?:^[ \t]*\|.+\|[ \t]*\n){2,}", _table_repl, s, flags=re.M)
    lists: list[str] = []

    def _stash_list(html: str) -> str:
        i = len(lists)
        lists.append(html)
        return f"\x00LIST{i}\x00\n\n"

    def _ul_repl(m: re.Match[str]) -> str:
        items = []
        for ln in m.group(0).strip().split("\n"):
            t = re.sub(r"^[-*+]\s+", "", ln).strip()
            if t:
                items.append(f"<li>{_escape_html(t)}</li>")
        return _stash_list("<ul>" + "".join(items) + "</ul>")

    def _ol_repl(m: re.Match[str]) -> str:
        items = []
        for ln in m.group(0).strip().split("\n"):
            t = re.sub(r"^\d+\.\s+", "", ln).strip()
            if t:
                items.append(f"<li>{_escape_html(t)}</li>")
        return _stash_list("<ol>" + "".join(items) + "</ol>")

    # Greedy + so consecutive items share one list (non-greedy caused 1. 1. 1.)
    s = re.sub(r"(?:^(?:[-*+])\s+.+(?:\n|$))+", _ul_repl, s, flags=re.M)
    s = re.sub(r"(?:^\d+\.\s+.+(?:\n|$))+", _ol_repl, s, flags=re.M)
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
    s = re.sub(r"^&gt;\s?(.+)$", r"<blockquote>\1</blockquote>", s, flags=re.M)
    parts = []
    for para in re.split(r"\n{2,}", s):
        p = para.strip()
        if not p:
            continue
        if re.match(r"^<(?:ul|ol|pre|h[1-4]|blockquote|div)", p):
            parts.append(p)
        elif re.fullmatch(r"\x00(?:TABLE|LIST)\d+\x00", p):
            parts.append(p)
        else:
            parts.append(f"<p>{p.replace(chr(10), '<br>')}</p>")
    s = "".join(parts)
    s = re.sub(r"\x00LIST(\d+)\x00", lambda m: lists[int(m.group(1))], s)
    s = re.sub(r"\x00TABLE(\d+)\x00", lambda m: tables[int(m.group(1))], s)
    s = re.sub(r"\x00FENCE(\d+)\x00", lambda m: fences[int(m.group(1))], s)
    # Inline md inside restored list items
    s = re.sub(r"(\*\*|__)(?=\S)([\s\S]*?\S)\1", r"<strong>\2</strong>", s)
    s = re.sub(r"(\*|_)(?=\S)([\s\S]*?\S)\1", r"<em>\2</em>", s)
    s = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", s)
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


def test_table_cells_escape_html() -> None:
    md = "| A | B |\n|---|---|\n| <script>x</script> | ok |\n"
    out = render_markdown_safe(md)
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_ordered_list_single_ol() -> None:
    """Consecutive 1. lines must become one <ol> (not four restarting at 1)."""
    md = (
        "Operator workflow (short)\n"
        "1. **Upsert**/select profile → activate it.\n"
        "1. Ensure **HTTP/HTTPS listener** is up.\n"
        "1. Generate payload that matches that profile.\n"
        "1. If you switch active profile mid-op, old implants keep old behavior.\n"
    )
    out = render_markdown_safe(md)
    assert out.count("<ol>") == 1
    assert out.count("</ol>") == 1
    assert out.count("<li>") == 4
    assert "<strong>Upsert</strong>" in out
    assert "<strong>HTTP/HTTPS listener</strong>" in out


def test_list_item_html_escaped() -> None:
    out = render_markdown_safe("1. <script>alert(1)</script>\n2. ok\n")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert out.count("<ol>") == 1


def test_unordered_list_single_ul() -> None:
    md = "- alpha\n- beta\n- gamma\n"
    out = render_markdown_safe(md)
    assert out.count("<ul>") == 1
    assert out.count("<li>") == 3


def test_chat_system_prompt_covers_platform() -> None:
    from squidc5.ai.ops_tools import CHAT_SYSTEM_PROMPT

    p = CHAT_SYSTEM_PROMPT
    assert "INKO" in p
    assert "Command" in p and "Control" in p
    assert "reverse_shell" in p
    assert "list_sessions" in p
    assert "activate_profile" in p
    assert "authorized" in p.lower()
