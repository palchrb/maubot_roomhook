import time, json, hashlib, secrets, jinja2, re
from typing import Optional, Dict, Any, Tuple
from urllib.parse import parse_qs

from aiohttp.web import Request, Response
from aiohttp import hdrs

from maubot import Plugin, PluginWebApp, MessageEvent
from maubot.handlers import command, event, web
from mautrix.types import (
    RoomID, UserID, EventType, MessageEventContent,
    PowerLevelStateEventContent, StateEvent
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
    return re.sub(r'([\\`*_{}\\[\\]()#+\\-!])', r'\\\1', str(s or ""))

def split_chunks(text: str, limit: int = 60000):
    text = text or ""
    if len(text) <= limit:
        return [text]
    return [text[i:i+limit] for i in range(0, len(text), limit)]

# ---------------- config ----------------

class PluginConfig(BaseProxyConfig):
    def do_update(self, h: ConfigUpdateHelper) -> None:
        # message defaults
        h.copy("message_format")   # markdown|html|plaintext
        h.copy("message_type")     # m.text|m.notice
        # admin / locality
        h.copy("restrict_admin_to_local")
        h.copy("restrict_commands_to_local")   # <--- NEW
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
        """Return homeserver domain without port."""
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
        """Return user's effective PL. Handles v12 owner and power_levels."""
        # 1) v12 owner/creator yields "infinite" PL
        owner_pl = await self._owner_pl_if_v12(room_id, user)
        if owner_pl is not None:
            return owner_pl

        # 2) Normal power_levels fetch (robust across return types)
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
        """Gate all !webhook commands to local users if configured."""
        # NOTE: RecursiveDict.get(key, default) — must include a default argument
        restrict = bool(self.config.get("restrict_commands_to_local", False))
        if restrict and not self._is_local(evt.sender):
            await evt.reply("Only local users are allowed to use webhook commands.")
            return False
        return True

    async def _owner_pl_if_v12(self, room_id: RoomID, user: UserID) -> Optional[int]:
        """Return a very high PL if user is a v12 creator (sender of m.room.create) or in additional_creators."""
        # 1) Fetch m.room.create (may be a full event, or only a content object without sender)
        ev = None
        try:
            ev = await self.client.get_state_event(room_id, EventType.ROOM_CREATE)
        except Exception:
            pass

        content: Dict[str, Any] = {}
        sender = ""

        if isinstance(ev, dict):
            # Full raw event
            sender = str(ev.get("sender", "") or "")
            c = ev.get("content")
            if isinstance(c, dict):
                content = c
        elif ev is not None:
            # Often RoomCreateStateEventContent without sender
            try:
                if hasattr(ev, "serialize"):
                    content = ev.serialize()  # type: ignore[attr-defined]
                else:
                    content = getattr(ev, "__dict__", {}) or {}
            except Exception:
                content = getattr(ev, "__dict__", {}) or {}

        # 2) Read room_version
        rv = (content or {}).get("room_version")
        try:
            rv_int = int(str(rv))
        except Exception:
            rv_int = None

        # 3) If v12+ and missing sender → fetch via raw /state
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

        # 4) v12 rule: sender of create or in additional_creators => effectively unlimited PL
        if rv_int is not None and rv_int >= 12:
            addl = (content or {}).get("additional_creators") or []
            if sender and (sender == str(user) or (isinstance(addl, list) and str(user) in addl)):
                return 1_000_000  # effectively unlimited
            return None

        # 5) Older rooms: 'creator' in content typically yields high PL (e.g. 100)
        creator = (content or {}).get("creator")
        if creator and creator == str(user):
            return 100

        return None

    async def _check_admin(self, evt: MessageEvent) -> bool:
        # First, ensure command locality if required
        if not await self._require_local_cmd(evt):
            return False
        # Adminlist always allowed
        if evt.sender in set(self.config["adminlist"] or []):
            return True
        # Then locality requirement for admin operations?
        if self.config["restrict_admin_to_local"] and not self._is_local(evt.sender):
            await evt.reply("Only local users are allowed to do this.")
            return False
        if not await self._has_required_pl(evt.room_id, evt.sender):
            await evt.reply(f"You need power level ≥ {self.config['pl_required']} in this room.")
            return False
        return True

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
            f"Done. Path endpoint changes to …/hook/{new_room}/… (Bearer /send endpoint is unaffected)."
        )
        try:
            await self.client.leave_room(evt.room_id)
        except Exception:
            pass

    # ---- invite/join hint ----
    @event.on(EventType.ROOM_MEMBER)
    async def on_member(self, evt: StateEvent) -> None:
        if evt.content.membership not in ("invite", "join"):
            return
        if evt.state_key != str(self.client.mxid):
            return
        await self.client.send_markdown(
            evt.room_id,
            "Hi! I can set up **per-room webhooks**.\n"
            "Commands: `!webhook help`."
        )

    # ---- convenience ----
    @command.new(name="roomid")
    async def cmd_roomid(self, evt: MessageEvent) -> None:
        await evt.reply(f"`{evt.room_id}`")

    @command.new(name="url")
    async def cmd_url(self, evt: MessageEvent) -> None:
        await evt.reply(f"`{self.webapp_url}send` and `{self.webapp_url}hook/{evt.room_id}/<name>/<token>`")

    # ---- commands ----
    @command.new(name="webhook", require_subcommand=True, help="Manage webhooks in this room")
    async def webhook(self, evt: MessageEvent) -> None:
        if not await self._require_local_cmd(evt):
            return
        await self.webhook_help(evt)

    @webhook.subcommand(name="perms", help="Show permission diagnostics")
    async def _webhook_perms(self, evt: MessageEvent) -> None:
        if not await self._require_local_cmd(evt):
            return
        in_adminlist = evt.sender in set(self.config["adminlist"] or [])
        local_ok = self._is_local(evt.sender)
        required = int(self.config["pl_required"] or 0)
        level = await self._get_user_pl(evt.room_id, evt.sender)
        await self.client.send_markdown(
            evt.room_id,
            "**Webhook permission diagnostics**\n"
            f"- You: `{evt.sender}` (server: `{self._user_domain(evt.sender)}`)\n"
            f"- In adminlist: **{'yes' if in_adminlist else 'no'}**\n"
            f"- Local OK (needs `{self.config['local_homeserver_domain']}`): **{'yes' if local_ok else 'no'}**\n"
            f"- Required PL: **{required}**\n"
            f"- Your PL in this room: **{level}**\n"
            f"- Result: **{'ALLOWED' if (in_adminlist or (local_ok and level >= required)) else 'DENIED'}**"
        )

    @webhook.subcommand(name="help", help="Show help")
    async def webhook_help(self, evt: MessageEvent) -> None:
        if not await self._require_local_cmd(evt):
            return
        text = (
            "**Per-room webhooks**\n\n"
            "- `!webhook list` — List hooks in this room\n"
            "- `!webhook add <name>` — Create a hook and show token (one-time display)\n"
            "- `!webhook save <name>` — Redact the token message in this room\n"
            "- `!webhook rotate <name>` — Rotate token for the hook\n"
            "- `!webhook revoke <name>` — Disable the hook\n"
            "- `!webhook show <name>` — Show endpoints without token\n"
            "- `!webhook set <name> fmt <markdown|html|plaintext>` — Set per-hook format\n"
            "- `!webhook set <name> type <m.text|m.notice>` — Set per-hook msgtype\n"
            "- `!webhook set <name> raw <on|off>` — Toggle per-hook raw mode (forward payload as code block)\n"
            "- `!webhook tpl <name> reset` — Clear per-hook Jinja template\n"
            "- `!webhook tpl <name> message <code>` — Set per-hook Jinja template\n"
            "- `!webhook perms` — Show permission diagnostics\n\n"
            "**HTTP**\n"
            "- `POST /send` with `Authorization: Bearer <token>` and JSON `{ \"message\": \"hi\" }`\n"
            "- Or: `POST /hook/{room_id}/{name}/{token}`\n"
        )
        await self.client.send_markdown(evt.room_id, text)

    @webhook.subcommand(name="list", help="List hooks in this room")
    async def webhook_list(self, evt: MessageEvent) -> None:
        if not await self._require_local_cmd(evt):
            return
        rid = str(evt.room_id)
        rows = await self.database.fetch(
            "SELECT name, revoked FROM room_hooks WHERE room_id=$1 ORDER BY name", rid
        )
        if not rows:
            await evt.reply("No hooks here yet. Use `!webhook add <name>`.")
        else:
            lines = [f"- **{r['name']}** — {'revoked' if r['revoked'] else 'active'}" for r in rows]
            await self.client.send_markdown(evt.room_id, "\n".join(lines))

    @webhook.subcommand(name="add", help="Create a new hook: !webhook add <name>")
    @command.argument("name", required=False)
    async def webhook_add(self, evt: MessageEvent, name: Optional[str] = None) -> None:
        if not await self._check_admin(evt):
            return
        if not name:
            await evt.reply("Usage: `!webhook add <name>`")
            return

        rid = str(evt.room_id)
        tok = secrets.token_urlsafe(24)
        tok_h = sha256_hex(tok)

        row = await self.database.fetchrow(
            "SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2", rid, name
        )
        if row and not row["revoked"]:
            await evt.reply("Hook already exists. Use `!webhook rotate <name>` or `!webhook show <name>`.")
            return

        if row:
            await self.database.execute("""
                UPDATE room_hooks
                   SET token_hash=$1, revoked=FALSE, created_by=$2, created_ts=$3, rotation=1,
                       raw=FALSE, fmt=NULL, msgtype=NULL, msg_tpl=NULL
                 WHERE room_id=$4 AND name=$5
            """, tok_h, str(evt.sender), now_ms(), rid, name)
        else:
            await self.database.execute("""
                INSERT INTO room_hooks (room_id, name, token_hash, revoked, created_by, created_ts, rotation)
                VALUES ($1, $2, $3, FALSE, $4, $5, 1)
            """, rid, name, tok_h, str(evt.sender), now_ms())

        url_send = f"{self.webapp_url}send"
        url_path = f"{self.webapp_url}hook/{rid}/{name}/{tok}"
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
        """, str(ev_id), rid, name)

    @webhook.subcommand(name="save", help="Redact the token message: !webhook save <name>")
    @command.argument("name", required=False)
    async def webhook_save(self, evt: MessageEvent, name: Optional[str] = None) -> None:
        if not await self._check_admin(evt):
            return
        if not name:
            await evt.reply("Usage: `!webhook save <name>`")
            return

        rid = str(evt.room_id)
        row = await self.database.fetchrow("""
            SELECT last_token_event_id FROM room_hooks WHERE room_id=$1 AND name=$2
        """, rid, name)
        if not row or not row["last_token_event_id"]:
            await evt.reply("No token message found to redact.")
            return
        ev_id = row["last_token_event_id"]
        await self.database.execute("""
            UPDATE room_hooks SET last_token_event_id=NULL WHERE room_id=$1 AND name=$2
        """, rid, name)
        try:
            await self.client.redact(evt.room_id, ev_id, reason="Hide token")
            await evt.reply("✅ Stored. The token message has been redacted.")
        except Exception as e:
            self.log.exception("Redact failed")
            await evt.reply(f"Token stored, but redaction failed: {e}")

    @webhook.subcommand(name="rotate", help="Rotate token: !webhook rotate <name>")
    @command.argument("name", required=False)
    async def webhook_rotate(self, evt: MessageEvent, name: Optional[str] = None) -> None:
        if not await self._check_admin(evt):
            return
        if not name:
            await evt.reply("Usage: `!webhook rotate <name>`")
            return

        rid = str(evt.room_id)
        tok = secrets.token_urlsafe(24)
        tok_h = sha256_hex(tok)
        row = await self.database.fetchrow("""
            SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2
        """, rid, name)
        if not row or row["revoked"]:
            await evt.reply("No active hook. Run `!webhook add <name>` first.")
            return
        await self.database.execute("""
            UPDATE room_hooks
               SET token_hash=$1, rotation=rotation+1, created_by=$2, created_ts=$3
             WHERE room_id=$4 AND name=$5
        """, tok_h, str(evt.sender), now_ms(), rid, name)

        url_send = f"{self.webapp_url}send"
        url_path = f"{self.webapp_url}hook/{rid}/{name}/{tok}"
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
        """, str(ev_id), rid, name)

    @webhook.subcommand(name="revoke", help="Disable a hook: !webhook revoke <name>")
    @command.argument("name", required=False)
    async def webhook_revoke(self, evt: MessageEvent, name: Optional[str] = None) -> None:
        if not await self._check_admin(evt):
            return
        if not name:
            await evt.reply("Usage: `!webhook revoke <name>`")
            return

        rid = str(evt.room_id)
        row = await self.database.fetchrow("""
            SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2
        """, rid, name)
        if not row:
            await evt.reply("No such hook.")
            return
        if row["revoked"]:
            await evt.reply("Hook is already disabled.")
            return
        await self.database.execute("""
            UPDATE room_hooks SET revoked=TRUE WHERE room_id=$1 AND name=$2
        """, rid, name)
        await evt.reply(f"🚫 Hook **{name}** disabled.")

    @webhook.subcommand(name="show", help="Show endpoints: !webhook show <name>")
    @command.argument("name", required=False)
    async def webhook_show(self, evt: MessageEvent, name: Optional[str] = None) -> None:
        if not await self._require_local_cmd(evt):
            return
        if not name:
            await evt.reply("Usage: `!webhook show <name>`")
            return
        rid = str(evt.room_id)
        row = await self.database.fetchrow("""
            SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2
        """, rid, name)
        if not row or row["revoked"]:
            await evt.reply("No active hook.")
            return
        url_send = f"{self.webapp_url}send"
        url_path = f"{self.webapp_url}hook/{rid}/{name}/<token>"
        await self.client.send_markdown(
            evt.room_id,
            f"**{name}**\n"
            f"- Bearer: `POST {url_send}` with `Authorization: Bearer <token>`\n"
            f"- Path:   `POST {url_path}`"
        )

    @webhook.subcommand(name="delete", help="Permanently delete a hook: !webhook delete <name>")
    @command.argument("name", required=False)
    async def webhook_delete(self, evt: MessageEvent, name: Optional[str] = None) -> None:
        if not await self._check_admin(evt):
            return
        if not name:
            await evt.reply("Usage: `!webhook delete <name>`")
            return

        rid = str(evt.room_id)
        row = await self.database.fetchrow(
            "SELECT 1 FROM room_hooks WHERE room_id=$1 AND name=$2",
            rid, name
        )
        if not row:
            await evt.reply("No such hook.")
            return

        # (Optional) neutralize token before delete for backups/replica hygiene:
        # await self.database.execute(
        #     "UPDATE room_hooks SET token_hash=$1 WHERE room_id=$2 AND name=$3",
        #     sha256_hex(secrets.token_urlsafe(32)), rid, name
        # )

        await self.database.execute(
            "DELETE FROM room_hooks WHERE room_id=$1 AND name=$2",
            rid, name
        )
        await evt.reply(f"🗑️ Deleted hook **{name}**.")

    @webhook.subcommand(name="set", help="Set per-hook format/type/raw: !webhook set <name> <fmt|type|raw> <value>")
    @command.argument("args", pass_raw=True, required=False)
    async def webhook_set(self, evt: MessageEvent, args: Optional[str] = None) -> None:
        if not await self._check_admin(evt):
            return
        if not args:
            await evt.reply("Usage: `!webhook set <name> <fmt|type|raw> <value>`")
            return

        parts = args.split(maxsplit=2)
        if len(parts) < 3:
            await evt.reply("Usage: `!webhook set <name> <fmt|type|raw> <value>`")
            return

        name, key, value = parts[0], parts[1].lower(), parts[2]
        rid = str(evt.room_id)
        exists = await self.database.fetchrow(
            "SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2", rid, name
        )
        if not exists or exists["revoked"]:
            await evt.reply("No active hook.")
            return

        if key in ("fmt", "format"):
            if value not in ("markdown", "html", "plaintext"):
                await evt.reply("Invalid fmt: use `markdown|html|plaintext`"); return
            await self.database.execute(
                "UPDATE room_hooks SET fmt=$1 WHERE room_id=$2 AND name=$3", value, rid, name
            )
        elif key == "type":
            if value not in ("m.text", "m.notice"):
                await evt.reply("Invalid type: use `m.text|m.notice`"); return
            await self.database.execute(
                "UPDATE room_hooks SET msgtype=$1 WHERE room_id=$2 AND name=$3", value, rid, name
            )
        elif key == "raw":
            v = value.lower()
            if v not in ("on", "off", "true", "false", "1", "0"):
                await evt.reply("Invalid raw: use `on|off`"); return
            flag = v in ("on", "true", "1")
            await self.database.execute(
                "UPDATE room_hooks SET raw=$1 WHERE room_id=$2 AND name=$3", flag, rid, name
            )
        else:
            await evt.reply("Unknown setting. Use `fmt|type|raw`"); return
        await evt.reply("✅ Updated.")

    @webhook.subcommand(name="tpl", help="Template: !webhook tpl <name> reset|message <code>")
    @command.argument("args", pass_raw=True, required=False)
    async def webhook_tpl(self, evt: MessageEvent, args: Optional[str] = None) -> None:
        if not await self._check_admin(evt):
            return
        if not args:
            await evt.reply("Usage: `!webhook tpl <name> reset|message <code>`")
            return

        parts = args.split(maxsplit=2)
        if len(parts) < 2:
            await evt.reply("Usage: `!webhook tpl <name> reset|message <code>`")
            return

        name, sub = parts[0], parts[1].lower()
        body = parts[2] if len(parts) >= 3 else None

        rid = str(evt.room_id)
        exists = await self.database.fetchrow(
            "SELECT revoked FROM room_hooks WHERE room_id=$1 AND name=$2", rid, name
        )
        if not exists or exists["revoked"]:
            await evt.reply("No active hook."); return

        if sub == "reset":
            await self.database.execute(
                "UPDATE room_hooks SET msg_tpl=NULL WHERE room_id=$1 AND name=$2", rid, name
            )
            await evt.reply("✅ Template cleared (using default simple message).")
            return

        if sub != "message" or not body:
            await evt.reply("Usage: `!webhook tpl <name> message <code>`"); return

        try:
            self.jinja.from_string(body)
        except Exception as e:
            await evt.reply(f"Template error: {e}"); return

        await self.database.execute(
            "UPDATE room_hooks SET msg_tpl=$1 WHERE room_id=$2 AND name=$3", body, rid, name
        )
        await evt.reply("✅ Template saved.")

    # ---------------- web handlers ----------------

    async def _parse_body(self, req: Request) -> Dict[str, Any]:
        ctype = (req.headers.get("Content-Type") or "").lower()
        raw = await req.read()
        if "application/json" in ctype:
            try:
                return json.loads(raw.decode() or "{}")
            except Exception:
                raise ValueError("invalid_json")
        if "application/x-www-form-urlencoded" in ctype:
            return {k: v[0] for k, v in parse_qs(raw.decode()).items()}
        if "text/plain" in ctype or not ctype:
            return {"raw": raw.decode(errors="replace")}
        try:
            return json.loads(raw.decode() or "{}")
        except Exception:
            return {"raw": raw.decode(errors="replace")}

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

    @web.post("/hook/{room_id}/{name}/{token}")
    async def handle_hook_path(self, req: Request) -> Response:
        if req.method not in set(self.config["allowed_methods"] or []):
            return Response(status=405, text="method_not_allowed")
        try:
            clamp_body(req, int(self.config["max_body_bytes"] or 0))
        except ValueError:
            return Response(status=413, text="payload_too_large")

        room_id = RoomID(req.match_info["room_id"])
        name = req.match_info["name"]
        token = req.match_info["token"]

        if not self._rate_ok(f"hook:{room_id}:{name}"):
            return Response(status=429, text="rate_limited")

        try:
            data = await self._parse_body(req)
        except ValueError as e:
            return Response(status=400, text=str(e))

        ok, err = await self._deliver_by_room_and_name(room_id, name, token, data)
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
            SELECT room_id, name, revoked, fmt, msgtype, msg_tpl, raw
              FROM room_hooks
             WHERE token_hash=$1
             LIMIT 1
        """, tok_h)
        if not row:
            return False, "bad_token"
        if row["revoked"]:
            return False, "revoked"
        return await self._render_and_send(row, data)

    async def _deliver_by_room_and_name(self, room_id: RoomID, name: str, token: str, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        row = await self.database.fetchrow("""
            SELECT room_id, name, revoked, fmt, msgtype, msg_tpl, raw, token_hash
              FROM room_hooks
             WHERE room_id=$1 AND name=$2
        """, str(room_id), name)
        if not row:
            return False, "bad_token"
        if row["revoked"]:
            return False, "revoked"
        if sha256_hex(token) != row["token_hash"]:
            return False, "bad_token"
        return await self._render_and_send(row, data)

    async def _render_and_send(self, row, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        room = RoomID(row["room_id"])
        fmt = (row["fmt"] or self.config["message_format"]).lower()
        msgtype = (row["msgtype"] or self.config["message_type"])  # "m.text" | "m.notice"

        # 1) Template wins
        tpl_src = row["msg_tpl"]
        if tpl_src:
            try:
                tpl = self.jinja.from_string(tpl_src)
                rendered = tpl.render({"json": data, "data": data, "escape_md": escape_md})
            except Exception as e:
                self.log.error(f"Template render error for {row['room_id']}/{row['name']}: {e}")
                return False, "template_error"
            for chunk in split_chunks(rendered):
                ok, err = await self._send_content(room, chunk, fmt, msgtype)
                if not ok: return False, err
            return True, None

        # 2) Raw mode per hook
        if bool(row.get("raw", False)):
            raw_text = json.dumps(data, ensure_ascii=False, indent=2)
            md = f"**Data received**\n```\n{raw_text}\n```"
            for chunk in split_chunks(md):
                ok, err = await self._send_content(room, chunk, "markdown", msgtype)
                if not ok: return False, err
            return True, None

        # 3) Generic: html > message|text > fallback raw
        if "html" in data and data["html"] is not None:
            return await self._send_content(room, str(data["html"]), "html", msgtype)

        body = data.get("message") or data.get("text")
        if body is not None:
            for chunk in split_chunks(str(body)):
                ok, err = await self._send_content(room, chunk, fmt, msgtype)
                if not ok: return False, err
            return True, None

        # 4) Fallback: raw as codeblock
        raw_text = json.dumps(data, ensure_ascii=False, indent=2)
        md = f"**Data received**\n```\n{raw_text}\n```"
        for chunk in split_chunks(md):
            ok, err = await self._send_content(room, chunk, "markdown", msgtype)
            if not ok: return False, err
        return True, None

    async def _send_content(self, room: RoomID, content: str, fmt: str, msgtype: str) -> Tuple[bool, Optional[str]]:
        try:
            if fmt == "markdown":
                await self.client.send_markdown(room, content, msgtype=msgtype)
            elif fmt == "html":
                await self.client.send_text(room, None, html=content, msgtype=msgtype)
            else:
                mec = MessageEventContent(msgtype=msgtype, body=content)
                await self.client.send_message(room, mec)
            return True, None
        except Exception:
            self.log.exception("Send failed")
            return False, "send_failed"
