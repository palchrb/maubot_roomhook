import time, json, hashlib, secrets, jinja2, re, html
from typing import Optional, Dict, Any, Tuple, List
from urllib.parse import parse_qs
from email.utils import parseaddr

from aiohttp.web import Request, Response
from aiohttp import hdrs

from maubot import Plugin, PluginWebApp, MessageEvent
from maubot.handlers import command, event, web
from mautrix.types import (
    RoomID, RoomAlias, UserID, EventType, MessageEventContent,
    PowerLevelStateEventContent, StateEvent, TextMessageEventContent, Format,
    MemberStateEventContent, Membership
)
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper

from .migrations import upgrade_table

# ---------------- utils ----------------

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def now_ms() -> int:
    return int(time.time() * 1000)

def clamp_body(req: Request, max_bytes: int) -> None:
    if max_bytes and req.content_length and req.content_length > max_bytes:
        raise ValueError("payload_too_large")

def parse_auth_token(req: Request, allow_query: bool) -> Optional[str]:
    h = req.headers.get(hdrs.AUTHORIZATION)
    if h and " " in h:
        typ, val = h.split(" ", 1)
        if typ.lower() == "bearer":
            return val
    if allow_query:
        tok = req.rel_url.query.get("token")
        if tok:
            return tok
    return None

def escape_md(s: str) -> str:
    return re.sub(r'([\\`*_{}\[\]()#+\-!])', r'\\\1', str(s or ""))

def split_chunks(text: str, limit: int = 60000) -> List[str]:
    text = text or ""
    if len(text) <= limit:
        return [text]
    return [text[i:i+limit] for i in range(0, len(text), limit)]

def trim_utf8_bytes(s: str, limit: int) -> str:
    """Trim string to at most `limit` UTF-8 bytes."""
    s = s or ""
    b = s.encode("utf-8")
    if len(b) <= limit:
        return s
    lo, hi = 0, len(s)
    while lo < hi:
        mid = (lo + hi) // 2
        if len(s[:mid].encode("utf-8")) <= limit:
            lo = mid + 1
        else:
            hi = mid
    return s[: lo - 1]

def parse_email_from(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not value:
        return None, None
    name, addr = parseaddr(str(value))
    name = name.strip() if name else None
    addr = addr.strip() if addr else None
    return (name or None), (addr or None)

# ---- tiny Markdown → HTML renderer (safe & minimal) ----

MD_BLOCK_TAGS = ("<pre", "<ul", "<ol", "<h1", "<h2", "<h3", "<h4", "<h5", "<h6", "<blockquote")

def _escape_html(s: str) -> str:
    return html.escape(s, quote=False)

def markdown_to_html(md: str) -> str:
    """
    Minimal and safe Markdown → HTML converter.
    Supported:
      - Headings: # .. ######  → <h1> .. <h6>
      - Fenced code blocks: ```lang?\n...\n``` → <pre><code>...</code></pre>
      - Inline code: `code` → <code>code</code>
      - Emphasis: **bold**, *italic*, ~~strike~~
      - Links: [label](url) (http/https/mailto only)
      - Autolink bare URLs: https://example.com → <a href="...">...</a>
      - Lists: unordered (-, *) and ordered (1.)
      - Blockquotes: lines starting with ">"
      - Horizontal rules: lines of --- or *** or ___
      - Paragraphs: double newlines split paragraphs, single newline → <br>
    Notes:
      - HTML is escaped first to avoid injection; only specific tags are emitted.
      - This is intentionally minimal; it does not support tables, nested lists, or advanced Markdown extensions.
    """
    if md is None:
        return ""
    text = str(md).replace("\r\n", "\n")

    # 1) Escape all HTML up front
    text = _escape_html(text)

    # 2) Fenced code blocks: ```lang?\n...\n```
    def _codeblock_repl(m):
        # group(1) is optional language (ignored), group(2) is the code (already escaped)
        code = m.group(2)
        return f"<pre><code>{code}</code></pre>"

    text = re.sub(r"```([^\n`]*)\n([\s\S]*?)```", _codeblock_repl, text, flags=re.MULTILINE)

    # 3) Inline code: `code` (not inside fenced blocks anymore)
    text = re.sub(r"(?<!`)`([^`\n]+)`(?!`)", r"<code>\1</code>", text)

    # 4) Emphasis
    text = re.sub(r"\*\*([^\n*]+)\*\*", r"<strong>\1</strong>", text)  # bold
    text = re.sub(r"\*([^\n*]+)\*", r"<em>\1</em>", text)              # italic
    text = re.sub(r"~~([^\n~]+)~~", r"<del>\1</del>", text)            # strike

    # 5) Links: [label](url) — allow only http/https/mailto
    def _link_repl(m):
        label = m.group(1)
        url = m.group(2)
        if not re.match(r"^(https?://|mailto:)", url, flags=re.IGNORECASE):
            return label  # do not link if scheme not allowed
        return f'<a href="{_escape_html(url)}" rel="noreferrer noopener">{label}</a>'

    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", _link_repl, text)

    # 6) Autolink bare URLs (simple heuristic, avoid double-linking)
    #    We try not to match inside an existing tag/attribute by excluding quotes/brackets around.
    def _autolink_repl(m):
        url = m.group(0)
        return f'<a href="{url}" rel="noreferrer noopener">{url}</a>'

    text = re.sub(
        r"(?<![\"'=])\bhttps?://[^\s<>()]+",
        _autolink_repl,
        text,
        flags=re.IGNORECASE,
    )

    # 7) Line-wise processing for headings, lists, blockquotes, and hr
    lines = text.split("\n")
    html_lines = []
    in_ul = False
    in_ol = False
    in_bq = False  # blockquote

    def _close_lists():
        nonlocal in_ul, in_ol
        if in_ul:
            html_lines.append("</ul>")
            in_ul = False
        if in_ol:
            html_lines.append("</ol>")
            in_ol = False

    def _close_blockquote():
        nonlocal in_bq
        if in_bq:
            html_lines.append("</blockquote>")
            in_bq = False

    for ln in lines:
        stripped = ln.strip()

        # Horizontal rule
        if re.match(r"^(\*\s*\*\s*\*|-{3,}|_{3,})\s*$", stripped):
            _close_lists()
            _close_blockquote()
            html_lines.append("<hr>")
            continue

        # Headings: ^#{1..6} <space> text
        m_h = re.match(r"^\s*(#{1,6})\s+(.+?)\s*$", ln)
        if m_h:
            _close_lists()
            _close_blockquote()
            level = len(m_h.group(1))
            title = m_h.group(2)
            html_lines.append(f"<h{level}>{title}</h{level}>")
            continue

        # Blockquote line: leading ">"
        m_bq = re.match(r"^\s*>\s?(.*)$", ln)
        if m_bq:
            _close_lists()
            if not in_bq:
                html_lines.append("<blockquote>")
                in_bq = True
            # Keep line content as-is; paragraph handling will come later
            html_lines.append(m_bq.group(1))
            continue

        # Ordered list: "1. item"
        m_ol = re.match(r"^\s*\d+\.\s+(.*)$", ln)
        if m_ol:
            _close_blockquote()
            if in_ul:
                html_lines.append("</ul>")
                in_ul = False
            if not in_ol:
                html_lines.append("<ol>")
                in_ol = True
            html_lines.append(f"<li>{m_ol.group(1)}</li>")
            continue

        # Unordered list: "- item" or "* item"
        m_ul = re.match(r"^\s*[-*]\s+(.*)$", ln)
        if m_ul:
            _close_blockquote()
            if in_ol:
                html_lines.append("</ol>")
                in_ol = False
            if not in_ul:
                html_lines.append("<ul>")
                in_ul = True
            html_lines.append(f"<li>{m_ul.group(1)}</li>")
            continue

        # Plain line
        _close_lists()
        # If we were in a blockquote and hit a non-">" line, close it before continuing
        _close_blockquote()
        html_lines.append(ln)

    # Close any open constructs
    _close_lists()
    _close_blockquote()

    text = "\n".join(html_lines)

    # 8) Paragraph splitting: wrap non-block sections in <p>, preserve single-line breaks as <br>
    parts = re.split(r"\n{2,}", text)
    out = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # If this chunk already starts with a block-level tag, keep as-is
        if any(part.lower().startswith(tag) for tag in MD_BLOCK_TAGS):
            out.append(part)
        else:
            out.append(f"<p>{part.replace('\n', '<br>')}</p>")

    return "".join(out)

# ---------------- config ----------------

class PluginConfig(BaseProxyConfig):
    def do_update(self, h: ConfigUpdateHelper) -> None:
        # message defaults
        h.copy("message_format")   # markdown|html|plaintext
        h.copy("message_type")     # m.text|m.notice
        # admin / locality
        h.copy("restrict_admin_to_local")
        h.copy("restrict_commands_to_local")
        h.copy("local_homeserver_domain")
        h.copy("pl_required")
        h.copy("adminlist")
        # http
        h.copy("rate_limit_per_minute")
        h.copy("max_body_bytes")
        h.copy("allowed_methods")
        h.copy("enable_path_token_route")
        h.copy("allow_query_token")

# ---------------- plugin ----------------

class RoomWebhooksPlugin(Plugin):
    config: PluginConfig
    webapp: PluginWebApp

    @classmethod
    def get_db_upgrade_table(cls):
        return upgrade_table

    @classmethod
    def get_config_class(cls):
        return PluginConfig

    async def start(self) -> None:
        self.config.load_and_update()
        self.jinja = jinja2.Environment(autoescape=True)
        self._rate: Dict[str, int] = {}  # simple in-memory rate bucket
        self.log.info(f"Webhook base URL: {self.webapp_url}")

    # ---- rate limiting (in-memory) ----
    def _rate_ok(self, key: str) -> bool:
        limit = int(self.config["rate_limit_per_minute"] or 0)
        if limit <= 0:
            return True
        minute = int(time.time() // 60)
        bucket = f"{key}:{minute}"
        count = self._rate.get(bucket, 0)
        if count >= limit:
            return False
        self._rate[bucket] = count + 1
        return True

    # ---- admin & local guards ----
    def _user_domain(self, user: UserID) -> str:
        try:
            server = str(user).split(":", 1)[1]
        except Exception:
            return ""
        return server.split(":", 1)[0].lower()

    def _is_local(self, user: UserID) -> bool:
        want = (self.config["local_homeserver_domain"] or "").lower()
        have = self._user_domain(user)
        if not want:
            return True
        return have == want

    async def _get_user_pl(self, room_id: RoomID, user: UserID) -> int:
        owner_pl = await self._owner_pl_if_v12(room_id, user)
        if owner_pl is not None:
            return owner_pl

        try:
            ev = await self.client.get_state_event(room_id, EventType.ROOM_POWER_LEVELS)
        except Exception as e:
            self.log.warning(f"PL fetch failed in {room_id} for {user}: {e}")
            return 0

        try:
            if isinstance(ev, PowerLevelStateEventContent):
                pls = ev
            elif isinstance(ev, dict):
                pls = PowerLevelStateEventContent.deserialize(ev)
            elif hasattr(ev, "content"):
                c = ev.content
                if isinstance(c, PowerLevelStateEventContent):
                    pls = c
                elif isinstance(c, dict):
                    pls = PowerLevelStateEventContent.deserialize(c)
                else:
                    pls = PowerLevelStateEventContent.deserialize(getattr(c, "__dict__", {}))
            else:
                pls = PowerLevelStateEventContent.deserialize(getattr(ev, "__dict__", {}))
        except Exception as e:
            self.log.warning(f"PL parse failed in {room_id} for {user}: {e}")
            return 0

        level = pls.users.get(user)
        if level is None:
            level = pls.users.get(str(user))
        if level is None:
            level = pls.users_default or 0
        try:
            return int(level or 0)
        except Exception:
            return 0

    async def _has_required_pl(self, room_id: RoomID, user: UserID) -> bool:
        required = int(self.config["pl_required"] or 0)
        if required <= 0:
            return True
        level = await self._get_user_pl(room_id, user)
        return level >= required

    async def _require_local_cmd(self, evt: MessageEvent) -> bool:
        restrict = bool(self.config.get("restrict_commands_to_local", False))
        if restrict and not self._is_local(evt.sender):
            await evt.reply("Only local users are allowed to use webhook commands.")
            return False
        return True

    async def _owner_pl_if_v12(self, room_id: RoomID, user: UserID) -> Optional[int]:
        ev = None
        try:
            ev = await self.client.get_state_event(room_id, EventType.ROOM_CREATE)
        except Exception:
            pass

        content: Dict[str, Any] = {}
        sender = ""

        if isinstance(ev, dict):
            sender = str(ev.get("sender", "") or "")
            c = ev.get("content")
            if isinstance(c, dict):
                content = c
        elif ev is not None:
            try:
                if hasattr(ev, "serialize"):
                    content = ev.serialize()  # type: ignore[attr-defined]
                else:
                    content = getattr(ev, "__dict__", {}) or {}
            except Exception:
                content = getattr(ev, "__dict__", {}) or {}

        rv = (content or {}).get("room_version")
        try:
            rv_int = int(str(rv))
        except Exception:
            rv_int = None

        if rv_int is not None and rv_int >= 12 and not sender:
            try:
                from urllib.parse import quote
                path = f"/_matrix/client/v3/rooms/{quote(str(room_id))}/state"
                raw_state = await self.client.api.request("GET", path)
                if isinstance(raw_state, list):
                    for e in raw_state:
                        if not isinstance(e, dict):
                            continue
                        if e.get("type") == "m.room.create" and (e.get("state_key", "") == ""):
                            sender = str(e.get("sender", "") or "")
                            c = e.get("content")
                            if not content and isinstance(c, dict):
                                content = c
                            break
            except Exception as ex:
                self.log.debug(f"v12 owner sender fetch via /state failed in {room_id}: {ex}")

        if rv_int is not None and rv_int >= 12:
            addl = (content or {}).get("additional_creators") or []
            if sender and (sender == str(user) or (isinstance(addl, list) and str(user) in addl)):
                return 1_000_000
            return None

        creator = (content or {}).get("creator")
        if creator and creator == str(user):
            return 100
        return None

    # --------- MEMBERSHIP (single source of truth) ---------

    def _membership_to_str(self, m: Any) -> Optional[str]:
        if m is None:
            return None
        if isinstance(m, Membership):
            return m.value.lower()
        try:
            return str(m).lower()
        except Exception:
            return None

    async def _get_membership(self, room_id: RoomID, user: UserID) -> Optional[str]:
        """
        Return 'join' | 'invite' | 'leave' | 'ban' | None using only get_state_event.
        """
        try:
            ev = await self.client.get_state_event(room_id, EventType.ROOM_MEMBER, state_key=str(user))
        except Exception as e:
            self.log.debug(f"membership fetch failed in {room_id} for {user}: {e}")
            return None

        if isinstance(ev, MemberStateEventContent):
            return self._membership_to_str(ev.membership)

        if isinstance(ev, StateEvent) and isinstance(ev.content, MemberStateEventContent):
            return self._membership_to_str(ev.content.membership)

        if isinstance(ev, StateEvent) and isinstance(ev.content, dict):
            v = ev.content.get("membership")
            return self._membership_to_str(v)

        if isinstance(ev, dict):
            c = ev.get("content", ev)
            if isinstance(c, dict):
                v = c.get("membership")
                return self._membership_to_str(v)

        return None

    # ---- room upgrade (tombstone) ----
    @event.on(EventType.ROOM_TOMBSTONE)
    async def tombstone(self, evt: StateEvent) -> None:
        new_room = evt.content.replacement_room
        if not new_room:
            return
        old_room = str(evt.room_id)
        await self.client.send_notice(evt.room_id, f"Room was upgraded → moving webhooks to {new_room} …")
        await self.database.execute(
            "UPDATE room_hooks SET room_id=$1 WHERE room_id=$2",
            new_room, old_room
        )
        await self.client.send_notice(
            evt.room_id,
            f"Done. Path endpoint changes to …/hook/{new_room}… (Bearer /send endpoint is unaffected)."
        )
        try:
            await self.client.leave_room(evt.room_id)
        except Exception:
            pass

    # ---- (removed) invite/join hint ----
    # No automatic greeting on invite/join anymore.

    # ---- convenience ----
    @command.new(name="roomid")
    async def cmd_roomid(self, evt: MessageEvent) -> None:
        await evt.reply(f"`{evt.room_id}`")

    @command.new(name="url")
    async def cmd_url(self, evt: MessageEvent) -> None:
        await evt.reply(f"`{self.webapp_url}send` and `{self.webapp_url}hook/<token>`")

    # ---- commands ----
    @command.new(name="webhook", require_subcommand=True, help="Manage webhooks in this room")
    async def webhook(self, evt: MessageEvent) -> None:
        if not await self._require_local_cmd(evt):
            return
        await self.webhook_help(evt)

    # ---- perms diag ----
    @webhook.subcommand(name="perms", help="Show permission diagnostics")
    @command.argument("tail", required=False, pass_raw=True)
    async def _webhook_perms(self, evt: MessageEvent, tail: Optional[str] = None) -> None:
        if not await self._require_local_cmd(evt):
            return
        parts = (tail or "").split()
        _, target = self._maybe_peel_target(parts)
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return

        in_adminlist = evt.sender in set(self.config["adminlist"] or [])
        local_ok = self._is_local(evt.sender)
        required = int(self.config["pl_required"] or 0)

        pl_here = await self._get_user_pl(evt.room_id, evt.sender)

        bot_mem = await self._get_membership(rid, self.client.mxid)
        you_mem = await self._get_membership(rid, evt.sender)
        bot_in_target = (bot_mem == "join")
        you_in_target = (you_mem == "join")

        pl_target = await self._get_user_pl(rid, evt.sender)

        read_ok = bot_in_target and you_in_target
        mutate_ok = bot_in_target and (in_adminlist or (local_ok and pl_target >= required))

        await self.client.send_markdown(
            evt.room_id,
            "**Webhook permission diagnostics**\n"
            f"- You: `{evt.sender}` (server: `{self._user_domain(evt.sender)}`)\n"
            f"- Target room: `{rid}`\n"
            f"- In adminlist: **{'yes' if in_adminlist else 'no'}**\n"
            f"- Local OK (needs `{self.config['local_homeserver_domain']}`): **{'yes' if local_ok else 'no'}**\n"
            f"- Bot membership: `{bot_mem or 'unknown'}` → in target: **{'yes' if bot_in_target else 'no'}**\n"
            f"- Your membership: `{you_mem or 'unknown'}` → in target: **{'yes' if you_in_target else 'no'}**\n"
            f"- Required PL in target: **{required}**\n"
            f"- Your PL in mgmt room: **{pl_here}** (informational)\n"
            f"- Your PL in target: **{pl_target}**\n"
            f"- Read access (target): **{'ALLOWED' if read_ok else 'DENIED'}**\n"
            f"- Mutate access (target): **{'ALLOWED' if mutate_ok else 'DENIED'}**"
        )

    @webhook.subcommand(name="help", help="Show help")
    async def webhook_help(self, evt: MessageEvent) -> None:
        if not await self._require_local_cmd(evt):
            return
        text = (
            "**Per-room webhooks**\n\n"
            "- `!webhook list [!room|#alias]` — List hooks\n"
            "- `!webhook add <name> [!room|#alias]` — Create a hook and show token (one-time display)\n"
            "- `!webhook save <name> [!room|#alias]` — Redact the token message\n"
            "- `!webhook rotate <name> [!room|#alias]` — Rotate token\n"
            "- `!webhook revoke <name> [!room|#alias]` — Disable the hook\n"
            "- `!webhook show <name> [!room|#alias]` — Show endpoints without token\n"
            "- `!webhook delete <name> [!room|#alias]` — Delete a hook\n"
            "- `!webhook set <name> <fmt|type|raw> <value> [!room|#alias]` — Per-hook fmt/type/raw\n"
            "- `!webhook tpl <name> reset|message <code> [!room|#alias]` — Manage Jinja template\n"
            "- `!webhook profile show <name> [!room|#alias]` — Show per-hook profile\n"
            "- `!webhook profile set <name> <displayname> [mxc://…] [!room|#alias]` — Set display/avatar\n"
            "- `!webhook profile reset <name> [!room|#alias]` — Reset to label/no avatar\n"
            "- `!webhook profile mode <name> <static|email_from> [!room|#alias]` — Profile mode\n"
            "- `!webhook profile prefix <name> <on|off> [!room|#alias]` — Toggle inline fallback prefix\n\n"
            "**HTTP**\n"
            "- `POST /send` with `Authorization: Bearer <token>` and JSON `{ \"message\": \"hi\" }`\n"
            "- Or: `POST /hook/<token>` (path token)\n"
            "- Optional per-request profile override: `\"_profile\": {\"id\":\"…\",\"displayname\":\"…\",\"avatar_url\":\"mxc://…\"}`\n"
        )
        await self.client.send_markdown(evt.room_id, text)

    # ---- list ----
    @webhook.subcommand(name="list", help="List hooks in this room or a target room")
    @command.argument("tail", required=False, pass_raw=True)
    async def webhook_list(self, evt: MessageEvent, tail: Optional[str] = None) -> None:
        if not await self._require_local_cmd(evt):
            return
        parts = (tail or "").split()
        _, target = self._maybe_peel_target(parts)
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return
        rows = await self.database.fetch(
            "SELECT name, revoked FROM room_hooks WHERE room_id=$1 ORDER BY name", str(rid)
        )
        if not rows:
            await evt.reply("No hooks here yet. Use `!webhook add <name>`.")
        else:
            lines = [f"- **{r['name']}** — {'revoked' if r['revoked'] else 'active'}" for r in rows]
            await self.client.send_markdown(evt.room_id, "\n".join(lines))

    # ---- add ----
    @webhook.subcommand(name="add", help="Create a new hook: !webhook add <name> [!room|#alias]")
    @command.argument("args", required=True, pass_raw=True)
    async def webhook_add(self, evt: MessageEvent, args: str) -> None:
        if not await self._check_admin_here(evt):
            return
        parts = args.split()
        if not parts:
            await evt.reply("Usage: `!webhook add <name> [!room|#alias]`")
            return
        parts2, target = self._maybe_peel_target(parts)
        if not parts2:
            await evt.reply("Usage: `!webhook add <name> [!room|#alias]`")
            return
        name = parts2[0]
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return

        rid_s = str(rid)
        tok = secrets.token_urlsafe(24)
        tok_h = sha256_hex(tok)

        row = await self.database.fetchrow(
            "SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2", rid_s, name
        )
        if row and not row["revoked"]:
            await evt.reply("Hook already exists. Use `!webhook rotate <name>` or `!webhook show <name>`.")
            return

        if row:
            await self.database.execute("""
                UPDATE room_hooks
                   SET token_hash=$1, revoked=FALSE, created_by=$2, created_ts=$3, rotation=1,
                       raw=FALSE, fmt=NULL, msgtype=NULL, msg_tpl=NULL,
                       label=COALESCE(label, $6), displayname=COALESCE(displayname, $6),
                       avatar_url=COALESCE(avatar_url, ''), profile_mode=COALESCE(profile_mode, 'static'),
                       profile_prefix_fallback=COALESCE(profile_prefix_fallback, TRUE)
                 WHERE room_id=$4 AND name=$5
            """, tok_h, str(evt.sender), now_ms(), rid_s, name, name)
        else:
            await self.database.execute("""
                INSERT INTO room_hooks (
                    room_id, name, token_hash, revoked, created_by, created_ts, rotation,
                    label, displayname, avatar_url, profile_mode, profile_prefix_fallback
                )
                VALUES ($1, $2, $3, FALSE, $4, $5, 1, $2, $2, '', 'static', TRUE)
            """, rid_s, name, tok_h, str(evt.sender), now_ms())

        url_send = f"{self.webapp_url}send"
        url_path = f"{self.webapp_url}hook/{tok}"
        text = (
            "🔗 **Webhook created**\n\n"
            f"**Primary (Bearer):**\n"
            f"`POST {url_send}`\n"
            f"Header: `Authorization: Bearer {tok}`\n"
            "Body (JSON): `{ \"message\": \"hi\" }`\n\n"
            f"**Simple (path token):**\n"
            f"`POST {url_path}`\n\n"
            f"**Token is shown only now:** `{tok}`\n"
            f"_Run `!webhook save {name}` to store and **redact** this message._"
        )
        ev_id = await self.client.send_markdown(evt.room_id, text)

        await self.database.execute("""
            UPDATE room_hooks SET last_token_event_id=$1 WHERE room_id=$2 AND name=$3
        """, str(ev_id), rid_s, name)

    # ---- save ----
    @webhook.subcommand(name="save", help="Redact the token message")
    @command.argument("args", required=True, pass_raw=True)
    async def webhook_save(self, evt: MessageEvent, args: str) -> None:
        if not await self._check_admin_here(evt):
            return
        parts = args.split()
        if not parts:
            await evt.reply("Usage: `!webhook save <name> [!room|#alias]`")
            return
        parts2, target = self._maybe_peel_target(parts)
        name = parts2[0]
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return

        rid_s = str(rid)
        row = await self.database.fetchrow("""
            SELECT last_token_event_id FROM room_hooks WHERE room_id=$1 AND name=$2
        """, rid_s, name)
        if not row or not row["last_token_event_id"]:
            await evt.reply("No token message found to redact.")
            return
        ev_id = row["last_token_event_id"]
        await self.database.execute("""
            UPDATE room_hooks SET last_token_event_id=NULL WHERE room_id=$1 AND name=$2
        """, rid_s, name)
        try:
            await self.client.redact(rid, ev_id, reason="Hide token")
            await evt.reply("✅ Stored. The token message has been redacted.")
        except Exception as e:
            self.log.exception("Redact failed")
            await evt.reply(f"Token stored, but redaction failed: {e}")

    # ---- rotate ----
    @webhook.subcommand(name="rotate", help="Rotate token")
    @command.argument("args", required=True, pass_raw=True)
    async def webhook_rotate(self, evt: MessageEvent, args: str) -> None:
        if not await self._check_admin_here(evt):
            return
        parts = args.split()
        if not parts:
            await evt.reply("Usage: `!webhook rotate <name> [!room|#alias]`")
            return
        parts2, target = self._maybe_peel_target(parts)
        name = parts2[0]
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return
        rid_s = str(rid)

        tok = secrets.token_urlsafe(24)
        tok_h = sha256_hex(tok)
        row = await self.database.fetchrow("""
            SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2
        """, rid_s, name)
        if not row or row["revoked"]:
            await evt.reply("No active hook. Run `!webhook add <name>` first.")
            return
        await self.database.execute("""
            UPDATE room_hooks
               SET token_hash=$1, rotation=rotation+1, created_by=$2, created_ts=$3
             WHERE room_id=$4 AND name=$5
        """, tok_h, str(evt.sender), now_ms(), rid_s, name)

        url_send = f"{self.webapp_url}send"
        url_path = f"{self.webapp_url}hook/{tok}"
        ev_id = await self.client.send_markdown(
            evt.room_id,
            f"🔁 New token for **{name}**\n\n"
            f"Bearer: `POST {url_send}` (Authorization: Bearer {tok})\n"
            f"Path:   `POST {url_path}`\n\n"
            f"**Token is shown only now:** `{tok}`\n"
            f"Run `!webhook save {name}` to redact."
        )
        await self.database.execute("""
            UPDATE room_hooks SET last_token_event_id=$1 WHERE room_id=$2 AND name=$3
        """, str(ev_id), rid_s, name)

    # ---- revoke ----
    @webhook.subcommand(name="revoke", help="Disable a hook")
    @command.argument("args", required=True, pass_raw=True)
    async def webhook_revoke(self, evt: MessageEvent, args: str) -> None:
        if not await self._check_admin_here(evt):
            return
        parts = args.split()
        if not parts:
            await evt.reply("Usage: `!webhook revoke <name> [!room|#alias]`")
            return
        parts2, target = self._maybe_peel_target(parts)
        name = parts2[0]
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return
        rid_s = str(rid)

        row = await self.database.fetchrow("""
            SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2
        """, rid_s, name)
        if not row:
            await evt.reply("No such hook.")
            return
        if row["revoked"]:
            await evt.reply("Hook is already disabled.")
            return
        await self.database.execute("""
            UPDATE room_hooks SET revoked=TRUE WHERE room_id=$1 AND name=$2
        """, rid_s, name)
        await evt.reply(f"🚫 Hook **{name}** disabled.")

    # ---- show ----
    @webhook.subcommand(name="show", help="Show endpoints")
    @command.argument("args", required=True, pass_raw=True)
    async def webhook_show(self, evt: MessageEvent, args: str) -> None:
        if not await self._require_local_cmd(evt):
            return
        parts = args.split()
        if not parts:
            await evt.reply("Usage: `!webhook show <name> [!room|#alias]`")
            return
        parts2, target = self._maybe_peel_target(parts)
        name = parts2[0]
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return

        rid_s = str(rid)
        row = await self.database.fetchrow("""
            SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2
        """, rid_s, name)
        if not row or row["revoked"]:
            await evt.reply("No active hook.")
            return
        url_send = f"{self.webapp_url}send"
        url_path = f"{self.webapp_url}hook/<token>"
        await self.client.send_markdown(
            evt.room_id,
            f"**{name}**\n"
            f"- Bearer: `POST {url_send}` with `Authorization: Bearer <token>`\n"
            f"- Path:   `POST {url_path}`"
        )

    # ---- delete ----
    @webhook.subcommand(name="delete", help="Permanently delete a hook")
    @command.argument("args", required=True, pass_raw=True)
    async def webhook_delete(self, evt: MessageEvent, args: str) -> None:
        if not await self._check_admin_here(evt):
            return
        parts = args.split()
        if not parts:
            await evt.reply("Usage: `!webhook delete <name> [!room|#alias]`")
            return
        parts2, target = self._maybe_peel_target(parts)
        name = parts2[0]
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return

        rid_s = str(rid)
        row = await self.database.fetchrow(
            "SELECT 1 FROM room_hooks WHERE room_id=$1 AND name=$2",
            rid_s, name
        )
        if not row:
            await evt.reply("No such hook.")
            return

        await self.database.execute(
            "DELETE FROM room_hooks WHERE room_id=$1 AND name=$2",
            rid_s, name
        )
        await evt.reply(f"🗑️ Deleted hook **{name}**.")

    # ---- set (fmt/type/raw) ----
    @webhook.subcommand(name="set", help="Set per-hook format/type/raw: !webhook set <name> <fmt|type|raw> <value> [!room|#alias]")
    @command.argument("args", pass_raw=True, required=False)
    async def webhook_set(self, evt: MessageEvent, args: Optional[str] = None) -> None:
        if not await self._check_admin_here(evt):
            return
        if not args:
            await evt.reply("Usage: `!webhook set <name> <fmt|type|raw> <value> [!room|#alias]`")
            return

        parts = args.split()
        parts2, target = self._maybe_peel_target(parts)
        if len(parts2) < 3:
            await evt.reply("Usage: `!webhook set <name> <fmt|type|raw> <value> [!room|#alias]`")
            return

        name, key, value = parts2[0], parts2[1].lower(), " ".join(parts2[2:])
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return
        rid_s = str(rid)

        exists = await self.database.fetchrow(
            "SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2", rid_s, name
        )
        if not exists or exists["revoked"]:
            await evt.reply("No active hook.")
            return

        if key in ("fmt", "format"):
            if value not in ("markdown", "html", "plaintext"):
                await evt.reply("Invalid fmt: use `markdown|html|plaintext`"); return
            await self.database.execute(
                "UPDATE room_hooks SET fmt=$1 WHERE room_id=$2 AND name=$3", value, rid_s, name
            )
        elif key == "type":
            if value not in ("m.text", "m.notice"):
                await evt.reply("Invalid type: use `m.text|m.notice`"); return
            await self.database.execute(
                "UPDATE room_hooks SET msgtype=$1 WHERE room_id=$2 AND name=$3", value, rid_s, name
            )
        elif key == "raw":
            v = value.lower()
            if v not in ("on", "off", "true", "false", "1", "0"):
                await evt.reply("Invalid raw: use `on|off`"); return
            flag = v in ("on", "true", "1")
            await self.database.execute(
                "UPDATE room_hooks SET raw=$1 WHERE room_id=$2 AND name=$3", flag, rid_s, name
            )
        else:
            await evt.reply("Unknown setting. Use `fmt|type|raw`"); return
        await evt.reply("✅ Updated.")

    # ---- template ----
    @webhook.subcommand(name="tpl", help="Template: !webhook tpl <name> reset|message <code> [!room|#alias]")
    @command.argument("args", pass_raw=True, required=False)
    async def webhook_tpl(self, evt: MessageEvent, args: Optional[str] = None) -> None:
        if not await self._check_admin_here(evt):
            return
        if not args:
            await evt.reply("Usage: `!webhook tpl <name> reset|message <code> [!room|#alias]`")
            return

        # Split the input into "head" (first line) and "body" (the rest)
        head, sep, body_rest = args.partition("\n")
        head_parts = head.split()
        head_parts2, target = self._maybe_peel_target(head_parts)

        if len(head_parts2) < 2:
            await evt.reply("Usage: `!webhook tpl <name> reset|message <code> [!room|#alias]`")
            return

        name = head_parts2[0]
        sub = head_parts2[1].lower()

        # For 'reset', we don't need a body
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return
        rid_s = str(rid)

        exists = await self.database.fetchrow(
            "SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2", rid_s, name
        )
        if not exists or exists["revoked"]:
            await evt.reply("No active hook.")
            return

        if sub == "reset":
            await self.database.execute(
                "UPDATE room_hooks SET msg_tpl=NULL WHERE room_id=$1 AND name=$2", rid_s, name
            )
            await evt.reply("✅ Template cleared (using default simple message).")
            return

        if sub != "message":
            await evt.reply("Usage: `!webhook tpl <name> message <code> [!room|#alias]`")
            return

        # The rest of the message (after the first line) is the template body – keep newlines!
        body = body_rest.lstrip("\n")
        if not body:
            await evt.reply("Usage: `!webhook tpl <name> message <code> [!room|#alias]`")
            return

        try:
            self.jinja.from_string(body)
        except Exception as e:
            await evt.reply(f"Template error: {e}")
            return

        await self.database.execute(
            "UPDATE room_hooks SET msg_tpl=$1 WHERE room_id=$2 AND name=$3", body, rid_s, name
        )
        await evt.reply("✅ Template saved.")

    # ---- profile commands (per hook) ----

    @webhook.subcommand(name="profile", help="Manage per-hook profile (label/display/avatar/mode/prefix)")
    async def webhook_profile_root(self, evt: MessageEvent) -> None:
        if not await self._require_local_cmd(evt):
            return
        await evt.reply(
            "Usage:\n"
            "`!webhook profile show <name> [!room|#alias]`\n"
            "`!webhook profile set <name> <displayname> [mxc://…] [!room|#alias]`\n"
            "`!webhook profile reset <name> [!room|#alias]`\n"
            "`!webhook profile mode <name> <static|email_from> [!room|#alias]`\n"
            "`!webhook profile prefix <name> <on|off> [!room|#alias]`"
        )

    @webhook_profile_root.subcommand(name="show", help="Show profile")
    @command.argument("args", required=True, pass_raw=True)
    async def webhook_profile_show(self, evt: MessageEvent, args: str) -> None:
        if not await self._require_local_cmd(evt):
            return
        parts = args.split()
        parts2, target = self._maybe_peel_target(parts)
        if not parts2:
            await evt.reply("Usage: `!webhook profile show <name> [!room|#alias]`")
            return
        name = parts2[0]
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return
        rid_s = str(rid)

        row = await self.database.fetchrow("""
            SELECT label, displayname, avatar_url, profile_mode, COALESCE(profile_prefix_fallback, TRUE) AS prefix_fb
              FROM room_hooks
             WHERE room_id=$1 AND name=$2
        """, rid_s, name)
        if not row:
            await evt.reply("No such hook.")
            return
        await self.client.send_markdown(
            evt.room_id,
            "**Profile**\n"
            f"- label: `{row['label'] or ''}`\n"
            f"- displayname: `{row['displayname'] or ''}`\n"
            f"- avatar mxc: `{(row['avatar_url'] or '') or '(none)'}`\n"
            f"- profile_mode: `{row['profile_mode'] or 'static'}`\n"
            f"- prefix_fallback: **{'on' if row['prefix_fb'] else 'off'}**"
        )

    @webhook_profile_root.subcommand(name="set", help="Set displayname and optional avatar")
    @command.argument("args", required=True, pass_raw=True)
    async def webhook_profile_set(self, evt: MessageEvent, args: str) -> None:
        if not await self._check_admin_here(evt):
            return
        parts = args.split()
        parts2, target = self._maybe_peel_target(parts)
        if len(parts2) < 2:
            await evt.reply("Usage: `!webhook profile set <name> <displayname> [mxc://…] [!room|#alias]`")
            return
        name = parts2[0]
        displayname = parts2[1]
        avatar_mxc = parts2[2] if len(parts2) >= 3 else None
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return
        rid_s = str(rid)

        if avatar_mxc and not avatar_mxc.startswith("mxc://"):
            await evt.reply("avatar must start with mxc:// or be omitted.")
            return
        displayname = trim_utf8_bytes(displayname, 255)
        await self.database.execute("""
            UPDATE room_hooks
               SET displayname=$1, avatar_url=$2
             WHERE room_id=$3 AND name=$4
        """, displayname, (avatar_mxc or ""), rid_s, name)
        await evt.reply(f"✅ Profile updated: **{displayname}** {(avatar_mxc or '').strip()}")

    @webhook_profile_root.subcommand(name="reset", help="Reset profile to label/no avatar")
    @command.argument("args", required=True, pass_raw=True)
    async def webhook_profile_reset(self, evt: MessageEvent, args: str) -> None:
        if not await self._check_admin_here(evt):
            return
        parts = args.split()
        parts2, target = self._maybe_peel_target(parts)
        if not parts2:
            await evt.reply("Usage: `!webhook profile reset <name> [!room|#alias]`")
            return
        name = parts2[0]
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return
        rid_s = str(rid)

        row = await self.database.fetchrow("""
            SELECT label FROM room_hooks WHERE room_id=$1 AND name=$2
        """, rid_s, name)
        if not row:
            await evt.reply("No such hook.")
            return
        await self.database.execute("""
            UPDATE room_hooks
               SET displayname=$1, avatar_url=''
             WHERE room_id=$2 AND name=$3
        """, row["label"], rid_s, name)
        await evt.reply(f"♻️ Profile reset to default ({row['label']})")

    @webhook_profile_root.subcommand(name="mode", help="Set profile mode")
    @command.argument("args", required=True, pass_raw=True)
    async def webhook_profile_mode(self, evt: MessageEvent, args: str) -> None:
        if not await self._check_admin_here(evt):
            return
        parts = args.split()
        parts2, target = self._maybe_peel_target(parts)
        if len(parts2) < 2:
            await evt.reply("Usage: `!webhook profile mode <name> <static|email_from> [!room|#alias]`")
            return
        name, v = parts2[0], parts2[1].lower()
        if v not in ("static", "email_from"):
            await evt.reply("Invalid mode: use `static|email_from`"); return
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return
        rid_s = str(rid)

        await self.database.execute(
            "UPDATE room_hooks SET profile_mode=$1 WHERE room_id=$2 AND name=$3",
            v, rid_s, name
        )
        await evt.reply(f"✅ profile_mode set to **{v}**.")

    @webhook_profile_root.subcommand(name="prefix", help="Toggle inline fallback")
    @command.argument("args", required=True, pass_raw=True)
    async def webhook_profile_prefix(self, evt: MessageEvent, args: str) -> None:
        if not await self._check_admin_here(evt):
            return
        parts = args.split()
        parts2, target = self._maybe_peel_target(parts)
        if len(parts2) < 2:
            await evt.reply("Usage: `!webhook profile prefix <name> <on|off> [!room|#alias]`")
            return
        name, v = parts2[0], parts2[1].lower()
        if v not in ("on", "off", "true", "false", "1", "0"):
            await evt.reply("Invalid value: use `on|off`"); return
        flag = v in ("on", "true", "1")
        rid = await self._resolve_target_room(evt, target)
        if not rid:
            return
        rid_s = str(rid)

        await self.database.execute(
            "UPDATE room_hooks SET profile_prefix_fallback=$1 WHERE room_id=$2 AND name=$3",
            flag, rid_s, name
        )
        await evt.reply(f"✅ prefix_fallback **{'on' if flag else 'off'}**.")

    # ---------------- web handlers ----------------

    async def _parse_body(self, req: Request) -> Dict[str, Any]:
        ctype = (req.headers.get("Content-Type") or "").lower()
        raw = await req.read()
        text = raw.decode(errors="replace")

        # If explicitly JSON, try JSON but fallback safely
        if "application/json" in ctype:
            try:
                return json.loads(text or "{}")
            except Exception:
                return {
                    "message": text,
                    "_raw": text,
                    "_parse_error": "invalid_json_but_treated_as_text",
                }

        # Form-encoded
        if "application/x-www-form-urlencoded" in ctype:
            return {k: v[0] for k, v in parse_qs(text).items()}

        # Plain text or missing
        if "text/plain" in ctype or not ctype:
            return {
                "message": text,
                "_raw": text,
            }

        # Unknown content-type → try JSON, fallback to raw
        try:
            return json.loads(text or "{}")
        except Exception:
            return {
                "message": text,
                "_raw": text,
                "_parse_error": "unknown_content_type_fallback",
            }


    @web.post("/send")
    async def handle_send(self, req: Request) -> Response:
        if req.method not in set(self.config["allowed_methods"] or []):
            return Response(status=405, text="method_not_allowed")
        try:
            clamp_body(req, int(self.config["max_body_bytes"] or 0))
        except ValueError:
            return Response(status=413, text="payload_too_large")

        token = parse_auth_token(req, self.config["allow_query_token"])
        if not token:
            return Response(status=401, text="missing_token")

        if not self._rate_ok(f"tok:{token[:10]}"):
            return Response(status=429, text="rate_limited")

        try:
            data = await self._parse_body(req)
        except ValueError as e:
            return Response(status=400, text=str(e))

        ok, err = await self._deliver_by_token(token, data)
        if not ok:
            return self._err_to_resp(err)
        return Response(status=204)

    @web.post("/hook/{token}")
    async def handle_hook_token(self, req: Request) -> Response:
        if req.method not in set(self.config["allowed_methods"] or []):
            return Response(status=405, text="method_not_allowed")
        try:
            clamp_body(req, int(self.config["max_body_bytes"] or 0))
        except ValueError:
            return Response(status=413, text="payload_too_large")

        token = req.match_info["token"]

        if not self._rate_ok(f"tok:{token[:10]}"):
            return Response(status=429, text="rate_limited")

        try:
            data = await self._parse_body(req)
        except ValueError as e:
            return Response(status=400, text=str(e))

        ok, err = await self._deliver_by_token(token, data)
        if not ok:
            return self._err_to_resp(err)
        return Response(status=204)

    def _err_to_resp(self, err: Optional[str]) -> Response:
        if err == "bad_token":
            return Response(status=401, text="bad_token")
        if err == "revoked":
            return Response(status=404, text="no_active_hook")
        if err == "template_error":
            return Response(status=400, text="template_error")
        if err == "send_failed":
            return Response(status=500, text="send_failed")
        if err == "empty":
            return Response(status=204)
        return Response(status=400, text=err or "bad_request")

    # ---------------- core delivery ----------------

    async def _deliver_by_token(self, token: str, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        tok_h = sha256_hex(token)
        row = await self.database.fetchrow("""
            SELECT room_id, name, revoked, fmt, msgtype, msg_tpl, raw,
                   label, displayname, avatar_url, profile_mode,
                   COALESCE(profile_prefix_fallback, TRUE) AS profile_prefix_fallback
              FROM room_hooks
             WHERE token_hash=$1
             LIMIT 1
        """, tok_h)
        if not row:
            return False, "bad_token"
        if row["revoked"]:
            return False, "revoked"
        return await self._render_and_send(row, data)

    def _resolve_profile_for_message(self, row: Dict[str, Any], data: Dict[str, Any]) -> Tuple[str, str, str]:
        label = (row.get("label") or row.get("name") or "").strip()
        stored_display = (row.get("displayname") or label or "").strip()
        stored_avatar = (row.get("avatar_url") or "").strip()
        profile_mode = (row.get("profile_mode") or "static").strip().lower()
        hook_name = (row.get("name") or "").strip()

        pr = data.get("_profile") if isinstance(data, dict) else None
        if isinstance(pr, dict):
            o_id = pr.get("id")
            o_dn = pr.get("displayname")
            o_av = pr.get("avatar_url")
            if o_dn:
                stored_display = str(o_dn).strip()
            if o_id:
                label = str(o_id).strip()
            if o_av and isinstance(o_av, str) and o_av.startswith("mxc://"):
                stored_avatar = o_av.strip()

        if profile_mode == "email_from":
            from_value = None
            candidate_paths = [
                ["from"],
                ["headers", "From"],
                ["email", "from"],
                ["gmail", "from"],
            ]
            for p in candidate_paths:
                t = data
                ok = True
                for k in p:
                    if isinstance(t, dict) and k in t:
                        t = t[k]
                    else:
                        ok = False
                        break
                if ok and t:
                    from_value = t
                    break

            name_from, addr_from = parse_email_from(from_value)
            if name_from:
                stored_display = name_from
            if addr_from:
                label = addr_from

        final_id = trim_utf8_bytes(label or hook_name or "hook", 255)
        final_dn = trim_utf8_bytes(stored_display or final_id, 255)
        final_av = stored_avatar if stored_avatar.startswith("mxc://") else ""
        return final_id, final_dn, final_av

    def _build_plain_and_html(self, displayname: str, content: str, fmt: str, prefix_enabled: bool) -> Tuple[str, str]:
        if fmt == "html":
            inner = str(content)
            if prefix_enabled:
                prefix = f'<strong data-mx-profile-fallback>{html.escape(displayname)}: </strong>'
                inner_stripped = inner.lstrip().lower()
                if any(inner_stripped.startswith(tag) for tag in MD_BLOCK_TAGS):
                    html_body = f"<p>{prefix}</p>{inner}"
                else:
                    html_body = f"<p>{prefix}{inner}</p>"
                plain = f"{displayname}: {self._strip_html_to_plain(inner)}"
            else:
                html_body = inner
                plain = self._strip_html_to_plain(inner)
            return plain, html_body

        if fmt == "markdown":
            inner = markdown_to_html(str(content))
            if prefix_enabled:
                prefix = f'<strong data-mx-profile-fallback>{html.escape(displayname)}: </strong>'
                inner_stripped = inner.lstrip().lower()
                if any(inner_stripped.startswith(tag) for tag in MD_BLOCK_TAGS):
                    html_body = f"<p>{prefix}</p>{inner}"
                else:
                    html_body = f"<p>{prefix}{inner}</p>"
                plain = f"{displayname}: {str(content)}"
            else:
                html_body = inner
                plain = str(content)
            return plain, html_body

        esc = html.escape(str(content))
        if prefix_enabled:
            html_body = f"<p><strong data-mx-profile-fallback>{html.escape(displayname)}: </strong>{esc}</p>"
            plain = f"{displayname}: {str(content)}"
        else:
            html_body = f"<p>{esc}</p>"
            plain = str(content)
        return plain, html_body

    def _strip_html_to_plain(self, html_in: str) -> str:
        s = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", html_in)
        s = re.sub(r"(?i)</\s*p\s*>", "\n", s)
        s = re.sub(r"(?i)<[^>]+>", "", s)
        s = html.unescape(s)
        return s

    async def _render_and_send(self, row, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        room = RoomID(row["room_id"])
        fmt = (row["fmt"] or self.config["message_format"]).lower()
        msgtype = (row["msgtype"] or self.config["message_type"])
        prefix_enabled = bool(row.get("profile_prefix_fallback", True))

        tpl_src = row["msg_tpl"]
        if tpl_src:
            try:
                tpl = self.jinja.from_string(tpl_src)
                rendered = tpl.render({"json": data, "data": data, "escape_md": escape_md})
            except Exception as e:
                self.log.error(f"Template render error for {row['room_id']}/{row['name']}: {e}")
                return False, "template_error"
            chunks = split_chunks(rendered)
            for chunk in chunks:
                ok, err = await self._send_profiled_content(room, row, chunk, fmt, msgtype, data, prefix_enabled)
                if not ok:
                    return False, err
            return True, None

        if bool(row.get("raw", False)):
            raw_text = json.dumps(data, ensure_ascii=False, indent=2)
            md = f"**Data received**\n```\n{raw_text}\n```"
            for chunk in split_chunks(md):
                ok, err = await self._send_profiled_content(room, row, chunk, "markdown", msgtype, data, prefix_enabled)
                if not ok:
                    return False, err
            return True, None

        if "html" in data and data["html"] is not None:
            ok, err = await self._send_profiled_content(room, row, str(data["html"]), "html", msgtype, data, prefix_enabled)
            return (ok, err)

        body = data.get("message") or data.get("text")
        if body is not None:
            for chunk in split_chunks(str(body)):
                ok, err = await self._send_profiled_content(room, row, chunk, fmt, msgtype, data, prefix_enabled)
                if not ok:
                    return False, err
            return True, None

        raw_text = json.dumps(data, ensure_ascii=False, indent=2)
        md = f"**Data received**\n```\n{raw_text}\n```"
        for chunk in split_chunks(md):
            ok, err = await self._send_profiled_content(room, row, chunk, "markdown", msgtype, data, prefix_enabled)
            if not ok:
                return False, err
        return True, None

    async def _send_profiled_content(
        self,
        room: RoomID,
        row: Dict[str, Any],
        content: str,
        fmt: str,
        msgtype: str,
        data: Dict[str, Any],
        prefix_enabled: bool,
    ) -> Tuple[bool, Optional[str]]:
        try:
            prof_id, prof_dn, prof_av = self._resolve_profile_for_message(row, data)
            plain, html_body = self._build_plain_and_html(prof_dn, content, fmt, prefix_enabled)

            mec = TextMessageEventContent(
                msgtype=msgtype,
                body=plain,
                format=Format.HTML,
                formatted_body=html_body,
            )
            mec["com.beeper.per_message_profile"] = {
                "id": prof_id,
                "displayname": prof_dn,
                "avatar_url": prof_av,
                "has_fallback": bool(prefix_enabled),
            }
            await self.client.send_message(room, mec)
            return True, None
        except Exception:
            self.log.exception("Send failed")
            return False, "send_failed"

    # --------- TARGET ROOM HELPERS ---------

    async def _resolve_target_room(self, evt: MessageEvent, target: Optional[str]) -> Optional[RoomID]:
        if not target:
            return evt.room_id
        target = target.strip()
        if target.startswith("!"):
            return RoomID(target)
        if target.startswith("#"):
            try:
                res = await self.client.resolve_room_alias(RoomAlias(target))
                rid = getattr(res, "room_id", None) or res["room_id"]
                return RoomID(rid)
            except Exception as e:
                await evt.reply(f"Failed to resolve room alias `{target}`: {e}")
                return None
        await evt.reply("Room target must be `!roomid` or `#alias` if provided.")
        return None

    def _maybe_peel_target(self, parts: List[str]) -> Tuple[List[str], Optional[str]]:
        if not parts:
            return parts, None
        last = parts[-1]
        if last.startswith("!") or last.startswith("#"):
            return parts[:-1], last
        return parts, None

    async def _check_admin_here(self, evt: MessageEvent) -> bool:
        if evt.sender in set(self.config["adminlist"] or []):
            return True
        if self.config["restrict_admin_to_local"] and not self._is_local(evt.sender):
            await evt.reply("Only local users are allowed to do this.")
            return False
        if not await self._has_required_pl(evt.room_id, evt.sender):
            await evt.reply(f"You need power level ≥ {self.config['pl_required']} in this room.")
            return False
        return True
