# maubot_roomhook
A maubot plugin for room specific webhooks configurable from any room, with possibility to set per message profile (name and avatar) per webhook to give it a much cooler visual! No more loads of messages from the same bot user, for clients that have incorporated this MSC it will show whatever profile you want it to show for a specific webhook.

There are already maubot webhook plugins, but I could mainly find versions that predominantly think that the maubot admin is the only user of the webhooks (with auth and all defined here, and no !help dialogue with the clients). But I wanted to have a webhook bot that my server's users can set up themselves, with authentication and all per room with just talking to the webhook bot. So that is what I have tried to do here!

Code is not beatiful, but it seems to work (but all functions are not battle tested yet..)

So this bot will allow you to;
- Invite the bot
- !webhook add "name" to generate a webhook config with bearer token, specific to this room only
- full url with tokens displayed, both with the option to use bearer token and inline url token if that is what is needed for your service
- Define all webhooks from a mgmt room of your choosing to avoid exposing tokens to the whole room

You can define in your config;
- Only allow users from your homeserver to use this bot
- PL needed to use bot
- Whether per-hook `fmt=html` (raw HTML into `formatted_body`) is allowed — off by default; only enable if every webhook source is trusted
- Whether the `/hook/<token>` path-token route is enabled (path tokens end up in proxy/access logs, browser history, etc.)
- PLus a bit more; this is not fully polished

### Notes on management rooms and tokens

`!webhook add <name> [!room|#alias]` posts the freshly generated token
into the room you ran the command in — not into the target room. That
is the whole point of the mgmt-room pattern: keep the token out of the
room it gives access to. But it does mean **every other member of your
mgmt room can read the token until you run `!webhook save <name>`**
(which redacts the token message). Use a private room you own as your
mgmt room, and run `save` immediately after `add`/`rotate`.

Admin/PL is checked against the **target room**, not the mgmt room.
Use `!webhook perms [!room|#alias]` to verify what the bot will let
you do.

Works in v12 rooms since Maubot works in v12 rooms..

### Install

Grab the latest `.mbp` from the
[Releases](https://github.com/palchrb/maubot_roomhook/releases) page
and upload it to your maubot instance via the web UI. A new release
is built automatically when the `version` field in `maubot.yaml`
is bumped on `main`.

### Build from source

```sh
zip -r vibb.me.roomwebhooks.mbp maubot.yaml base-config.yaml plugin \
    -x 'plugin/__pycache__/*' 'plugin/*.pyc'
```

Then upload the resulting `.mbp` to maubot.

Feel free to contact me [on Matrix](https://matrix.to/#/#whatever:vibb.me)
