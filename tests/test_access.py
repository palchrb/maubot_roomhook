"""Tests for the mutation access check and `!webhook move`.

These drive the real plugin methods against small in-memory fakes for
room membership, power levels and the database.
"""

import asyncio
import logging
from types import SimpleNamespace

from plugin.bot import RoomWebhooksPlugin

HERE = "!here:hs"
SRC = "!src:hs"
DST = "!dst:hs"
BOT = "@bot:hs"
USER = "@user:hs"


class FakeDB:
    def __init__(self, rows):
        # {(room_id, name): {"revoked": bool, "token_hash": str}}
        self.rows = dict(rows)

    async def fetchrow(self, query, room_id, name):
        return self.rows.get((room_id, name))

    async def execute(self, query, new_room, old_room, name):
        assert "UPDATE room_hooks SET room_id" in query
        self.rows[(new_room, name)] = self.rows.pop((old_room, name))


def make_plugin(*, members=(), admin_in=(), adminlist=(), rows=None):
    """members: {(room, user)} that are joined. admin_in: rooms where USER
    has the required power level."""
    p = RoomWebhooksPlugin.__new__(RoomWebhooksPlugin)
    p.config = {
        "adminlist": list(adminlist),
        "restrict_admin_to_local": True,
        "local_homeserver_domain": "hs",
        "pl_required": 50,
    }
    p.client = SimpleNamespace(mxid=BOT)
    p.log = logging.getLogger("test")
    p.database = FakeDB(rows or {})
    p.replies = []
    members = set(members)
    admin_in = set(admin_in)

    async def _get_membership(room_id, user):
        return "join" if (str(room_id), str(user)) in members else "leave"

    async def _has_required_pl(room_id, user):
        return str(room_id) in admin_in

    async def _reply(evt, text, markdown=False):
        p.replies.append(text)

    p._get_membership = _get_membership
    p._has_required_pl = _has_required_pl
    p._reply = _reply
    return p


def evt(sender=USER, room=HERE):
    return SimpleNamespace(sender=sender, room_id=room)


def run(coro):
    return asyncio.run(coro)


# ---- _check_admin_here ----

def test_admin_check_current_room_needs_only_pl():
    p = make_plugin(admin_in={HERE})
    assert run(p._check_admin_here(evt(), HERE)) is True


def test_admin_check_current_room_denied_without_pl():
    p = make_plugin()
    assert run(p._check_admin_here(evt(), HERE)) is False


def test_admin_check_remote_room_requires_membership_not_just_pl():
    # Former moderator: still has the power level, but has left the room.
    p = make_plugin(members={(SRC, BOT)}, admin_in={SRC})
    assert run(p._check_admin_here(evt(), SRC)) is False
    assert "must be a member" in p.replies[-1]


def test_admin_check_remote_room_allowed_for_member_with_pl():
    p = make_plugin(members={(SRC, BOT), (SRC, USER)}, admin_in={SRC})
    assert run(p._check_admin_here(evt(), SRC)) is True


def test_admin_check_remote_room_requires_bot_joined():
    p = make_plugin(members={(SRC, USER)}, admin_in={SRC})
    assert run(p._check_admin_here(evt(), SRC)) is False
    assert "Bot is not joined" in p.replies[-1]


def test_adminlist_bypasses_pl_and_membership():
    p = make_plugin(members={(SRC, BOT)}, adminlist=[USER])
    assert run(p._check_admin_here(evt(), SRC)) is True


def test_adminlist_still_requires_bot_joined():
    p = make_plugin(adminlist=[USER])
    assert run(p._check_admin_here(evt(), SRC)) is False
    assert "Bot is not joined" in p.replies[-1]


def test_non_local_user_denied_even_with_pl():
    p = make_plugin(admin_in={HERE})
    assert run(p._check_admin_here(evt(sender="@user:elsewhere"), HERE)) is False


# ---- move ----

HOOK = {"revoked": False, "token_hash": "abc"}
BOTH = {(SRC, BOT), (SRC, USER), (DST, BOT), (DST, USER)}


def test_move_from_mgmt_room_keeps_token():
    p = make_plugin(members=BOTH, admin_in={SRC, DST}, rows={(SRC, "kuma"): dict(HOOK)})
    run(p._move_hook(evt(), f"kuma {SRC} {DST}"))
    assert (SRC, "kuma") not in p.database.rows
    assert p.database.rows[(DST, "kuma")]["token_hash"] == "abc"
    assert "Moved hook" in p.replies[-1]


def test_move_from_current_room_with_single_room_argument():
    p = make_plugin(
        members={(DST, BOT), (DST, USER)},
        admin_in={SRC, DST},
        rows={(SRC, "kuma"): dict(HOOK)},
    )
    run(p._move_hook(evt(room=SRC), f"kuma {DST}"))
    assert (DST, "kuma") in p.database.rows


def test_move_denied_without_admin_in_destination():
    p = make_plugin(members=BOTH, admin_in={SRC}, rows={(SRC, "kuma"): dict(HOOK)})
    run(p._move_hook(evt(), f"kuma {SRC} {DST}"))
    assert (SRC, "kuma") in p.database.rows
    assert (DST, "kuma") not in p.database.rows


def test_move_denied_without_admin_in_source():
    p = make_plugin(members=BOTH, admin_in={DST}, rows={(SRC, "kuma"): dict(HOOK)})
    run(p._move_hook(evt(), f"kuma {SRC} {DST}"))
    assert (SRC, "kuma") in p.database.rows


def test_move_refuses_name_conflict_in_destination():
    rows = {(SRC, "kuma"): dict(HOOK), (DST, "kuma"): {"revoked": False, "token_hash": "other"}}
    p = make_plugin(members=BOTH, admin_in={SRC, DST}, rows=rows)
    run(p._move_hook(evt(), f"kuma {SRC} {DST}"))
    assert p.database.rows[(SRC, "kuma")]["token_hash"] == "abc"
    assert p.database.rows[(DST, "kuma")]["token_hash"] == "other"
    assert "already exists" in p.replies[-1]


def test_move_unknown_hook():
    p = make_plugin(members=BOTH, admin_in={SRC, DST})
    run(p._move_hook(evt(), f"nope {SRC} {DST}"))
    assert "No hook named" in p.replies[-1]


def test_move_same_room_refused():
    p = make_plugin(admin_in={SRC}, rows={(SRC, "kuma"): dict(HOOK)})
    run(p._move_hook(evt(room=SRC), f"kuma {SRC}"))
    assert "already in that room" in p.replies[-1]
    assert (SRC, "kuma") in p.database.rows


def test_move_usage_when_destination_or_name_missing():
    p = make_plugin()
    for args in ("kuma", DST, f"a b {DST}"):
        run(p._move_hook(evt(), args))
        assert p.replies[-1].startswith("Usage:")
