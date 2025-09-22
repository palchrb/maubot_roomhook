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
