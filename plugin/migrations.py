from mautrix.util.async_db import UpgradeTable, Scheme, Connection

upgrade_table = UpgradeTable()


async def _add_column(conn: Connection, scheme: Scheme, table: str, column_def: str) -> None:
    """ALTER TABLE … ADD COLUMN, portable across Postgres and SQLite.

    SQLite does not support `ADD COLUMN IF NOT EXISTS`, so for SQLite the
    plain form is used and a duplicate-column error is treated as success.
    """
    if scheme == Scheme.SQLITE:
        try:
            await conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")
        except Exception as e:
            if "duplicate column" not in str(e).lower():
                raise
    else:
        await conn.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column_def}")


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
    await _add_column(conn, scheme, "room_hooks", "parser TEXT DEFAULT 'auto'")
    if scheme == Scheme.SQLITE:
        await _add_column(conn, scheme, "room_hooks", "raw INTEGER DEFAULT 0")
    else:
        await _add_column(conn, scheme, "room_hooks", "raw BOOLEAN DEFAULT FALSE")


@upgrade_table.register(description="Add per-hook profile fields and profile_mode")
async def upgrade_v4(conn: Connection, scheme: Scheme) -> None:
    # Profile fields: label, displayname, avatar_url
    await _add_column(conn, scheme, "room_hooks", "label TEXT")
    await _add_column(conn, scheme, "room_hooks", "displayname TEXT")
    await _add_column(conn, scheme, "room_hooks", "avatar_url TEXT")
    # Profile mode: 'static' (default) or 'email_from'
    await _add_column(conn, scheme, "room_hooks", "profile_mode TEXT DEFAULT 'static'")


@upgrade_table.register(description="Add profile_prefix_fallback toggle")
async def upgrade_v5(conn: Connection, scheme: Scheme) -> None:
    if scheme == Scheme.SQLITE:
        await _add_column(conn, scheme, "room_hooks", "profile_prefix_fallback INTEGER DEFAULT 1")
    else:
        await _add_column(conn, scheme, "room_hooks", "profile_prefix_fallback BOOLEAN DEFAULT TRUE")


@upgrade_table.register(description="Index on room_id for list queries")
async def upgrade_v6(conn: Connection, scheme: Scheme) -> None:
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_room_hooks_room_id ON room_hooks (room_id)")


@upgrade_table.register(description="Track which room the last token message was posted in")
async def upgrade_v7(conn: Connection, scheme: Scheme) -> None:
    # `!webhook add/rotate` post the token into the room the command was run
    # in (mgmt room), which may differ from the hook's target room. `save`
    # needs to know where to redact.
    await _add_column(conn, scheme, "room_hooks", "last_token_room_id TEXT")
