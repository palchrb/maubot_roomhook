from mautrix.util.async_db import UpgradeTable, Scheme, Connection

upgrade_table = UpgradeTable()

@upgrade_table.register(description="Initial room_hooks table")
async def upgrade_v1(conn: Connection, scheme: Scheme) -> None:
    if scheme == Scheme.SQLITE:
        await conn.execute("""
            CREATE TABLE room_hooks (
                room_id TEXT NOT NULL,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_by TEXT NOT NULL,
                created_ts BIGINT NOT NULL,
                rotation INTEGER NOT NULL DEFAULT 1,
                last_token_event_id TEXT,
                fmt TEXT,
                msgtype TEXT,
                msg_tpl TEXT,
                PRIMARY KEY (room_id, name)
            )
        """)
    else:
        await conn.execute("""
            CREATE TABLE room_hooks (
                room_id TEXT NOT NULL,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                revoked BOOLEAN NOT NULL DEFAULT FALSE,
                created_by TEXT NOT NULL,
                created_ts BIGINT NOT NULL,
                rotation INTEGER NOT NULL DEFAULT 1,
                last_token_event_id TEXT,
                fmt TEXT,
                msgtype TEXT,
                msg_tpl TEXT,
                PRIMARY KEY (room_id, name)
            )
        """)

@upgrade_table.register(description="Index on token_hash")
async def upgrade_v2(conn: Connection, scheme: Scheme) -> None:
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_room_hooks_token_hash ON room_hooks (token_hash)")

@upgrade_table.register(description="Add parser and raw flags per hook")
async def upgrade_v3(conn: Connection, scheme: Scheme) -> None:
    await conn.execute("ALTER TABLE room_hooks ADD COLUMN IF NOT EXISTS parser TEXT DEFAULT 'auto'")
    if scheme == Scheme.SQLITE:
        await conn.execute("ALTER TABLE room_hooks ADD COLUMN IF NOT EXISTS raw INTEGER DEFAULT 0")
    else:
        await conn.execute("ALTER TABLE room_hooks ADD COLUMN IF NOT EXISTS raw BOOLEAN DEFAULT FALSE")

@upgrade_table.register(description="Add per-hook profile fields and profile_mode")
async def upgrade_v4(conn: Connection, scheme: Scheme) -> None:
    # Profile fields: label, displayname, avatar_url
    await conn.execute("ALTER TABLE room_hooks ADD COLUMN IF NOT EXISTS label TEXT")
    await conn.execute("ALTER TABLE room_hooks ADD COLUMN IF NOT EXISTS displayname TEXT")
    await conn.execute("ALTER TABLE room_hooks ADD COLUMN IF NOT EXISTS avatar_url TEXT")
    # Profile mode: 'static' (default) or 'email_from'
    await conn.execute("ALTER TABLE room_hooks ADD COLUMN IF NOT EXISTS profile_mode TEXT DEFAULT 'static'")

@upgrade_table.register(description="Add profile_prefix_fallback toggle")
async def upgrade_v5(conn: Connection, scheme: Scheme) -> None:
    if scheme == Scheme.SQLITE:
        await conn.execute("ALTER TABLE room_hooks ADD COLUMN IF NOT EXISTS profile_prefix_fallback INTEGER DEFAULT 1")
    else:
        await conn.execute("ALTER TABLE room_hooks ADD COLUMN IF NOT EXISTS profile_prefix_fallback BOOLEAN DEFAULT TRUE")
