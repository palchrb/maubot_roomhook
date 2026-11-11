"""Tests for power-level resolution, including room version 12 creators
and the pre-v11 `creator` field. Drives the real `_get_user_pl` against
a fake Matrix client."""

import asyncio
import logging
from types import SimpleNamespace

from mautrix.errors import MForbidden, MNotFound
from mautrix.types import (
    EventType,
    PowerLevelStateEventContent,
    RoomCreateStateEventContent,
)

from plugin.bot import PL_ROOM_CREATOR, RoomWebhooksPlugin, room_version_int

V12_ROOM = "!31hneApxJ_1o-63DmFrpeqnkFfWppnzWso1JvH3ogLM"
V12_CREATE_EVENT = "%2431hneApxJ_1o-63DmFrpeqnkFfWppnzWso1JvH3ogLM"
OLD_ROOM = "!old:hs"
CREATOR = "@creator:hs"
CO_CREATOR = "@cocreator:hs"
MOD = "@mod:hs"
NOBODY = "@nobody:hs"


class FakeClient:
    def __init__(self, *, create, power_levels, create_sender=CREATOR, event_by_id=True):
        self.create = create
        self.power_levels = power_levels
        self.create_sender = create_sender
        self.event_by_id = event_by_id
        self.requests = []
        self.state_fetches = []
        self.api = SimpleNamespace(request=self._request)

    async def get_state_event(self, room_id, event_type, state_key=""):
        self.state_fetches.append(event_type)
        if event_type == EventType.ROOM_CREATE:
            if self.create is None:
                raise MForbidden(403, "not in room")
            return RoomCreateStateEventContent.deserialize(self.create)
        if event_type == EventType.ROOM_POWER_LEVELS:
            if self.power_levels is None:
                raise MNotFound(404, "no power levels")
            return PowerLevelStateEventContent.deserialize(self.power_levels)
        raise AssertionError(event_type)

    async def _request(self, method, path):
        self.requests.append(path)
        if "/event/" in path:
            if not self.event_by_id:
                raise MNotFound(404, "event not found")
            return {"type": "m.room.create", "sender": self.create_sender, "content": self.create}
        if path.endswith("/state"):
            if not self.create_sender:
                raise MForbidden(403, "nope")
            return [
                {"type": "m.room.member", "state_key": MOD, "sender": MOD, "content": {}},
                {"type": "m.room.create", "state_key": "", "sender": self.create_sender, "content": self.create},
            ]
        raise AssertionError(path)


def make_plugin(client):
    p = RoomWebhooksPlugin.__new__(RoomWebhooksPlugin)
    p.client = client
    p.log = logging.getLogger("test")
    p._create_cache = {}
    return p


def pl(p, room, user):
    return asyncio.run(p._get_user_pl(room, user))


V12_CREATE = {"room_version": "12", "additional_creators": [CO_CREATOR]}
V12_PLS = {"users": {MOD: 50}, "users_default": 0}


# ---- room_version_int ----

def test_room_version_int():
    assert room_version_int("12") == 12
    assert room_version_int("10") == 10
    assert room_version_int(None) == 0
    assert room_version_int("org.example.custom") == 0


# ---- room version 12 ----

def test_v12_creator_has_unlimited_power():
    c = FakeClient(create=V12_CREATE, power_levels=V12_PLS)
    assert pl(make_plugin(c), V12_ROOM, CREATOR) == PL_ROOM_CREATOR


def test_v12_additional_creator_has_unlimited_power():
    c = FakeClient(create=V12_CREATE, power_levels=V12_PLS)
    assert pl(make_plugin(c), V12_ROOM, CO_CREATOR) == PL_ROOM_CREATOR


def test_v12_other_users_use_power_levels():
    c = FakeClient(create=V12_CREATE, power_levels=V12_PLS)
    p = make_plugin(c)
    assert pl(p, V12_ROOM, MOD) == 50
    assert pl(p, V12_ROOM, NOBODY) == 0


def test_v12_create_event_fetched_by_id_not_full_state():
    c = FakeClient(create=V12_CREATE, power_levels=V12_PLS)
    pl(make_plugin(c), V12_ROOM, CREATOR)
    assert len(c.requests) == 1
    assert c.requests[0].endswith(f"/event/{V12_CREATE_EVENT}")


def test_v12_create_info_is_cached_per_room():
    c = FakeClient(create=V12_CREATE, power_levels=V12_PLS)
    p = make_plugin(c)
    for user in (CREATOR, CO_CREATOR, MOD, NOBODY):
        pl(p, V12_ROOM, user)
    assert len(c.requests) == 1
    assert c.state_fetches.count(EventType.ROOM_CREATE) == 1


def test_v12_falls_back_to_full_state_when_event_lookup_fails():
    c = FakeClient(create=V12_CREATE, power_levels=V12_PLS, event_by_id=False)
    assert pl(make_plugin(c), V12_ROOM, CREATOR) == PL_ROOM_CREATOR
    assert c.requests[-1].endswith("/state")


def test_v12_unknown_creator_fails_closed_and_is_not_cached():
    c = FakeClient(create=V12_CREATE, power_levels=V12_PLS, create_sender="", event_by_id=False)
    p = make_plugin(c)
    assert pl(p, V12_ROOM, CREATOR) == 0
    assert p._create_cache == {}


# ---- room versions before 12 ----

def test_legacy_creator_uses_power_levels_event():
    create = {"room_version": "10", "creator": CREATOR}
    c = FakeClient(create=create, power_levels={"users": {CREATOR: 100, MOD: 50}})
    p = make_plugin(c)
    assert pl(p, OLD_ROOM, CREATOR) == 100
    assert pl(p, OLD_ROOM, MOD) == 50
    assert c.requests == []


def test_legacy_demoted_creator_does_not_keep_admin():
    create = {"room_version": "10", "creator": CREATOR}
    c = FakeClient(create=create, power_levels={"users": {MOD: 100}, "users_default": 0})
    assert pl(make_plugin(c), OLD_ROOM, CREATOR) == 0


def test_legacy_creator_gets_100_only_without_power_levels_event():
    create = {"room_version": "10", "creator": CREATOR}
    c = FakeClient(create=create, power_levels=None)
    p = make_plugin(c)
    assert pl(p, OLD_ROOM, CREATOR) == 100
    assert pl(p, OLD_ROOM, MOD) == 0


def test_v11_room_uses_power_levels_only():
    c = FakeClient(create={"room_version": "11"}, power_levels={"users": {CREATOR: 100}})
    p = make_plugin(c)
    assert pl(p, OLD_ROOM, CREATOR) == 100
    assert pl(p, OLD_ROOM, NOBODY) == 0


def test_unreadable_create_event_falls_back_to_power_levels():
    c = FakeClient(create=None, power_levels={"users": {MOD: 50}})
    assert pl(make_plugin(c), OLD_ROOM, MOD) == 50
