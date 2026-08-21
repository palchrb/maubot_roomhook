"""Unit tests for the side-effect-free helpers in plugin/bot.py.

These exercise the pure utility functions only — anything that needs a
maubot client, aiohttp request, or database is covered by manual
testing against a live homeserver.
"""

from plugin.bot import (
    sha256_hex,
    escape_md,
    split_chunks,
    trim_utf8_bytes,
    parse_email_from,
    markdown_to_html,
    _escape_html,
    RoomWebhooksPlugin,
)


# ---- sha256_hex ----

def test_sha256_hex_known_vectors():
    assert sha256_hex("") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert sha256_hex("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_hex_is_stable():
    s = "some-webhook-token"
    assert sha256_hex(s) == sha256_hex(s)


# ---- escape_md ----

def test_escape_md_escapes_specials():
    assert escape_md("hello *world*") == r"hello \*world\*"
    assert escape_md("a[b](c)") == r"a\[b\]\(c\)"
    assert escape_md("# heading") == r"\# heading"


def test_escape_md_passthrough_plain():
    assert escape_md("nothing special") == "nothing special"


def test_escape_md_handles_empty_and_none():
    assert escape_md("") == ""
    assert escape_md(None) == ""


# ---- split_chunks ----

def test_split_chunks_no_split_when_short():
    assert split_chunks("hi", 60000) == ["hi"]


def test_split_chunks_splits_long_strings():
    s = "x" * 25
    chunks = split_chunks(s, 10)
    assert chunks == ["xxxxxxxxxx", "xxxxxxxxxx", "xxxxx"]


def test_split_chunks_handles_none():
    assert split_chunks(None) == [""]


def test_split_chunks_exact_multiple():
    s = "abcdef"
    assert split_chunks(s, 3) == ["abc", "def"]


def test_split_chunks_is_byte_based_and_utf8_safe():
    # "æ" is 2 bytes in UTF-8: a 4-byte limit fits 2 chars per chunk.
    s = "æ" * 10
    chunks = split_chunks(s, 4)
    assert "".join(chunks) == s
    for c in chunks:
        assert len(c.encode("utf-8")) <= 4
        c.encode("utf-8").decode("utf-8")  # never split mid-codepoint
    assert chunks == ["ææ"] * 5


def test_split_chunks_default_limit_stays_below_matrix_event_cap():
    # 20k 4-byte emoji = 80kB — must be split into <=16000-byte chunks.
    s = "🎉" * 20000
    chunks = split_chunks(s)
    assert "".join(chunks) == s
    assert all(len(c.encode("utf-8")) <= 16000 for c in chunks)


# ---- trim_utf8_bytes ----

def test_trim_utf8_bytes_no_op_within_limit():
    assert trim_utf8_bytes("hello", 100) == "hello"


def test_trim_utf8_bytes_truncates_ascii():
    assert trim_utf8_bytes("hello world", 5) == "hello"


def test_trim_utf8_bytes_respects_multibyte_boundary():
    # "æ" is 2 bytes in UTF-8; "hi æ" is 5 bytes total.
    out = trim_utf8_bytes("hi æ", 4)
    # Result must be valid UTF-8 and not exceed the byte cap.
    encoded = out.encode("utf-8")
    assert len(encoded) <= 4
    # And the multi-byte char must not be partially included.
    out.encode("utf-8").decode("utf-8")  # would raise if mid-codepoint


def test_trim_utf8_bytes_empty_and_none():
    assert trim_utf8_bytes("", 10) == ""
    assert trim_utf8_bytes(None, 10) == ""


# ---- parse_email_from ----

def test_parse_email_from_name_and_addr():
    name, addr = parse_email_from("Alice <alice@example.com>")
    assert name == "Alice"
    assert addr == "alice@example.com"


def test_parse_email_from_bare_addr():
    name, addr = parse_email_from("alice@example.com")
    assert name is None
    assert addr == "alice@example.com"


def test_parse_email_from_empty_and_none():
    assert parse_email_from(None) == (None, None)
    assert parse_email_from("") == (None, None)


# ---- markdown_to_html ----

def test_markdown_to_html_escapes_raw_html():
    out = markdown_to_html("<script>alert(1)</script>")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_markdown_to_html_bold_italic_strike():
    out = markdown_to_html("**bold** and *italic* and ~~gone~~")
    assert "<strong>bold</strong>" in out
    assert "<em>italic</em>" in out
    assert "<del>gone</del>" in out


def test_markdown_to_html_inline_code():
    out = markdown_to_html("`code`")
    assert "<code>code</code>" in out


def test_markdown_to_html_link_allows_http():
    out = markdown_to_html("[click](https://example.com)")
    assert 'href="https://example.com"' in out
    assert "rel=\"noreferrer noopener\"" in out


def test_markdown_to_html_link_rejects_javascript_scheme():
    out = markdown_to_html("[bad](javascript:alert(1))")
    # No href should be emitted at all for disallowed schemes.
    assert "href=" not in out
    # The label survives as text.
    assert "bad" in out


def test_markdown_to_html_link_rejects_data_scheme():
    out = markdown_to_html("[bad](data:text/html,<script>1</script>)")
    assert "href=" not in out


def test_markdown_to_html_heading():
    out = markdown_to_html("# Hello")
    assert "<h1>Hello</h1>" in out


def test_markdown_to_html_handles_none():
    assert markdown_to_html(None) == ""


def test_markdown_to_html_url_label_not_double_linked():
    out = markdown_to_html("[https://example.com](https://example.com)")
    assert out.count("<a ") == 1
    assert 'href="https://example.com"' in out


def test_markdown_to_html_autolinks_bare_url():
    out = markdown_to_html("see https://example.com now")
    assert '<a href="https://example.com"' in out


# ---- _escape_html ----

def test_escape_html_lt_gt_amp():
    assert _escape_html("<b>") == "&lt;b&gt;"
    assert _escape_html("a & b") == "a &amp; b"


def test_escape_html_leaves_quotes_alone():
    # The plugin uses quote=False so " and ' are preserved.
    assert _escape_html('a"b') == 'a"b'
    assert _escape_html("a'b") == "a'b"


# ---- _make_prefix_html / _wrap_html_with_prefix ----

def test_make_prefix_html_escapes_displayname():
    out = RoomWebhooksPlugin._make_prefix_html("<script>")
    assert "&lt;script&gt;" in out
    assert "<strong data-mx-profile-fallback>" in out


def test_wrap_inline_content_gets_p_with_prefix():
    out = RoomWebhooksPlugin._wrap_html_with_prefix("hello", "PRE: ")
    assert out == "<p>PRE: hello</p>"


def test_wrap_block_content_gets_separate_p():
    out = RoomWebhooksPlugin._wrap_html_with_prefix("<pre>code</pre>", "PRE: ")
    assert out == "<p>PRE: </p><pre>code</pre>"


def test_wrap_p_content_injects_into_existing_p_when_requested():
    out = RoomWebhooksPlugin._wrap_html_with_prefix("<p>hi</p>", "PRE: ", inject_into_p=True)
    assert out == "<p>PRE: hi</p>"


# ---- rate limiter / flood protection ----

def _bare_plugin() -> RoomWebhooksPlugin:
    p = RoomWebhooksPlugin.__new__(RoomWebhooksPlugin)
    p._rate = {}
    return p


def test_rate_ok_disabled_when_limit_zero():
    p = _bare_plugin()
    assert all(p._rate_ok("k", 0) for _ in range(1000))


def test_rate_ok_burst_then_blocks():
    p = _bare_plugin()
    results = [p._rate_ok("hook:room:name", 5) for _ in range(8)]
    # burst defaults to min(limit, 10) = 5 → 5 through, then throttled
    assert results == [True] * 5 + [False] * 3


def test_rate_ok_explicit_burst_caps_initial_burst():
    p = _bare_plugin()
    results = [p._rate_ok("k", 60, 2) for _ in range(4)]
    assert results == [True, True, False, False]


def test_rate_ok_buckets_are_independent():
    p = _bare_plugin()
    assert [p._rate_ok("a", 1), p._rate_ok("b", 1)] == [True, True]
    assert [p._rate_ok("a", 1), p._rate_ok("b", 1)] == [False, False]


def test_rate_ok_refills_over_time(monkeypatch):
    import plugin.bot as botmod
    t = [0.0]
    monkeypatch.setattr(botmod.time, "monotonic", lambda: t[0])
    p = _bare_plugin()
    # 60/min = 1 token per second, burst 2
    assert p._rate_ok("k", 60, 2)
    assert p._rate_ok("k", 60, 2)
    assert not p._rate_ok("k", 60, 2)   # bucket empty
    t[0] = 1.0                          # one second later → one token back
    assert p._rate_ok("k", 60, 2)
    assert not p._rate_ok("k", 60, 2)
    t[0] = 120.0                        # long idle → refills only to burst cap
    assert p._rate_ok("k", 60, 2)
    assert p._rate_ok("k", 60, 2)
    assert not p._rate_ok("k", 60, 2)


def test_capped_chunks_truncates_and_notes():
    p = _bare_plugin()
    p.config = {"max_chunks_per_message": 3}
    chunks = p._capped_chunks("x" * 16000 * 6)
    assert len(chunks) == 3
    assert "truncated" in chunks[-1]


def test_capped_chunks_no_cap_when_zero():
    p = _bare_plugin()
    p.config = {"max_chunks_per_message": 0}
    assert len(p._capped_chunks("x" * 16000 * 6)) == 6


def test_wrap_p_content_prefix_with_backslash_is_literal():
    # A displayname containing backslashes/group refs must not be
    # interpreted by re.sub (would raise "bad escape" or expand groups).
    out = RoomWebhooksPlugin._wrap_html_with_prefix(
        "<p>hi</p>", r"a\1b\q: ", inject_into_p=True
    )
    assert out == r"<p>a\1b\q: hi</p>"


def test_wrap_p_content_without_inject_treats_as_inline():
    # `<p` is not in MD_BLOCK_TAGS, so without inject_into_p the helper
    # takes the inline branch. This matches the existing html-fmt
    # behaviour before the refactor.
    out = RoomWebhooksPlugin._wrap_html_with_prefix("<p>hi</p>", "PRE: ")
    assert out == "<p>PRE: <p>hi</p></p>"
